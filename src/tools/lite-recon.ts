/**
 * 轻量级侦察工具 - 无需外部工具依赖
 * 使用纯 Node.js 和公共 API 实现
 */

import axios from 'axios';
import * as dns from 'dns';
import { promisify } from 'util';
import { httpClient, getRandomUserAgent } from '../utils/http-client.js';

const resolveDns = promisify(dns.resolve);

export interface SubdomainResult {
  subdomain: string;
  ips: string[];
  source: string;
}

export interface WebFingerprint {
  url: string;
  status: number;
  title: string;
  server: string;
  technologies: string[];
  headers: Record<string, string>;
}

/**
 * 使用 crt.sh 查询子域名
 */
export async function enumerateSubdomainsCrtSh(domain: string): Promise<SubdomainResult[]> {
  // crt.sh 对大查询（如 360.cn 有数千条记录）可能返回 502，需要重试
  const MAX_RETRIES = 3;
  let lastError: any;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      // crt.sh 对大型域名可能需要 50 秒以上，超时设为 90 秒
      const response = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, {
        timeout: 90000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SRCHunter/1.0' }
      });

      // crt.sh 返回非 JSON（如 502 HTML）时，response.data 是字符串
      if (typeof response.data === 'string') {
        throw new Error(`crt.sh 返回非 JSON 响应（可能是 502/限流）`);
      }

      const subdomains = new Set<string>();

      for (const entry of response.data) {
        const nameValue = entry.name_value;
        // 按换行分割证书 SAN 记录
        const domains = nameValue.split('\n')
          .map((d: string) => d.trim().toLowerCase())
          .filter((d: string) => d.endsWith(domain))
          // 过滤噪声：邮箱、带空格/标点的非域名记录
          .filter((d: string) => !d.includes('@') && !d.includes(' ') && /^[\w.*-]+$/.test(d));

        for (const sub of domains) {
          // 去掉通配符前缀 *.xxx → xxx
          const normalized = sub.startsWith('*.') ? sub.slice(2) : sub;
          subdomains.add(normalized);
        }
      }

      // 并发解析 DNS（限制并发数，避免打爆本地 DNS）
      const domainList = Array.from(subdomains);
      const results: SubdomainResult[] = [];
      const CONCURRENCY = 20;

      for (let i = 0; i < domainList.length; i += CONCURRENCY) {
        const batch = domainList.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.allSettled(
          batch.map(async (sub): Promise<SubdomainResult> => {
            let ips: string[] = [];
            try {
              ips = await resolveDns(sub, 'A');
            } catch (err) {
              // DNS 解析失败，跳过
            }
            return { subdomain: sub, ips, source: 'crt.sh' };
          })
        );
        for (const r of batchResults) {
          if (r.status === 'fulfilled') {
            results.push(r.value);
          }
        }
      }

      // 按字母排序
      results.sort((a, b) => a.subdomain.localeCompare(b.subdomain));

      return results;
    } catch (error: any) {
      lastError = error;
      if (attempt < MAX_RETRIES - 1) {
        // 指数退避重试
        const waitMs = 3000 * Math.pow(2, attempt);
        await new Promise(resolve => setTimeout(resolve, waitMs));
        continue;
      }
    }
  }

  throw new Error(`crt.sh 查询失败（已重试 ${MAX_RETRIES} 次）: ${lastError?.message}`);
}

/**
 * Web 指纹识别
 */
export async function fingerprintWeb(url: string): Promise<WebFingerprint> {
  try {
    const response = await httpClient.get(url);

    // 提取标题
    const titleMatch = response.data.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : '';

    // 提取服务器信息
    const serverHeader = response.headers['server'];
    const server = typeof serverHeader === 'string' ? serverHeader : 'Unknown';

    // 简单的技术栈识别
    const technologies = detectTechnologies(response.data, response.headers);

    // 转换 headers 为字符串类型
    const headersObj: Record<string, string> = {};
    for (const [key, value] of Object.entries(response.headers)) {
      headersObj[key] = String(value);
    }

    return {
      url,
      status: response.status,
      title,
      server,
      technologies,
      headers: headersObj
    };
  } catch (error) {
    throw new Error(`Web 指纹识别失败: ${error}`);
  }
}

/**
 * 检测技术栈
 */
function detectTechnologies(html: string, headers: Record<string, any>): string[] {
  const technologies: string[] = [];

  // 框架检测
  if (html.includes('react')) technologies.push('React');
  if (html.includes('vue')) technologies.push('Vue.js');
  if (html.includes('angular')) technologies.push('Angular');
  if (html.includes('jquery')) technologies.push('jQuery');
  if (html.includes('bootstrap')) technologies.push('Bootstrap');

  // 服务器检测
  const server = headers['server'] || '';
  if (server.includes('nginx')) technologies.push('Nginx');
  if (server.includes('Apache')) technologies.push('Apache');
  if (server.includes('IIS')) technologies.push('IIS');

  // CMS 检测
  if (html.includes('wp-content')) technologies.push('WordPress');
  if (html.includes('Joomla')) technologies.push('Joomla');
  if (html.includes('Drupal')) technologies.push('Drupal');

  // 其他特征
  if (headers['x-powered-by']) {
    technologies.push(`Powered by: ${headers['x-powered-by']}`);
  }

  return technologies;
}

/**
 * 提取 JavaScript 文件中的 API 端点
 */
export async function extractApiEndpoints(url: string): Promise<string[]> {
  try {
    const response = await httpClient.get(url);

    const html = response.data;
    const endpoints = new Set<string>();

    // 提取 <script src="...">
    const scriptMatches = html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi);
    for (const match of scriptMatches) {
      endpoints.add(match[1]);
    }

    // 如果是 JS 文件，提取 API 路径
    if (url.endsWith('.js')) {
      // 匹配常见 API 路径模式
      const apiPatterns = [
        /["'](\/api\/[^"']+)["']/g,
        /["'](\/v\d+\/[^"']+)["']/g,
        /["']([^"']*\/graphql[^"']*)["']/g
      ];

      for (const pattern of apiPatterns) {
        const matches = html.matchAll(pattern);
        for (const match of matches) {
          endpoints.add(match[1]);
        }
      }
    }

    return Array.from(endpoints);
  } catch (error) {
    throw new Error(`API 端点提取失败: ${error}`);
  }
}

/**
 * 简单端口扫描（使用 TCP 连接尝试）
 */
export async function scanPorts(host: string, ports: number[]): Promise<number[]> {
  const net = require('net');
  const openPorts: number[] = [];

  for (const port of ports) {
    const isOpen = await new Promise<boolean>((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, host);
    });

    if (isOpen) {
      openPorts.push(port);
    }
  }

  return openPorts;
}
