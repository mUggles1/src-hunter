import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import axios from 'axios';
import * as cheerio from 'cheerio';
import {
  SubdomainResult,
  PortScanResult,
  FingerprintResult,
  EndpointResult,
  DirectoryScanResult,
} from '../types.js';
import { WhitelistManager } from '../security/whitelist.js';
import { RateLimitManager, AdaptiveRateLimiter } from '../security/rate-limit.js';
import { AuditLogger } from '../security/audit-log.js';
import { logger } from '../utils/logger.js';

const execAsync = promisify(exec);

export class ReconTools {
  private whitelistManager: WhitelistManager;
  private rateLimitManager: RateLimitManager;
  private auditLogger: AuditLogger;
  private adaptiveLimiter: AdaptiveRateLimiter;

  constructor(
    whitelistManager: WhitelistManager,
    rateLimitManager: RateLimitManager,
    auditLogger: AuditLogger
  ) {
    this.whitelistManager = whitelistManager;
    this.rateLimitManager = rateLimitManager;
    this.auditLogger = auditLogger;
    this.adaptiveLimiter = new AdaptiveRateLimiter(1000, 10000);
  }

  /**
   * 子域名枚举
   */
  public async enumerateSubdomains(
    domain: string,
    tools?: string[],
    timeoutMs: number = 300000
  ): Promise<SubdomainResult> {
    const startTime = Date.now();

    // 1. 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(domain);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('enumerate-subdomains', domain, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 2. 频率限制
    const canProceed = await this.rateLimitManager.consume('enumerate-subdomains', domain);
    if (!canProceed) {
      throw new Error('Rate limit exceeded. Please wait before retrying.');
    }

    // 3. 选择工具
    const selectedTools = tools?.includes('all') || !tools
      ? ['subfinder', 'amass']
      : tools;

    const allSubdomains = new Set<string>();
    let usedTool = '';

    try {
      // 使用 subfinder
      if (selectedTools.includes('subfinder')) {
        logger.info(`Running subfinder on ${domain}`);
        try {
          const { stdout } = await execAsync(
            `subfinder -d ${domain} -silent -timeout ${Math.floor(timeoutMs / 1000)}`,
            { timeout: timeoutMs }
          );
          stdout.split('\n').forEach(line => {
            const sub = line.trim();
            if (sub) allSubdomains.add(sub);
          });
          usedTool = 'subfinder';
        } catch (error: any) {
          logger.warn('Subfinder failed', error.message);
        }
      }

      // 使用 amass
      if (selectedTools.includes('amass')) {
        logger.info(`Running amass on ${domain}`);
        try {
          const { stdout } = await execAsync(
            `amass enum -passive -d ${domain} -timeout ${Math.floor(timeoutMs / 60000)}`,
            { timeout: timeoutMs }
          );
          stdout.split('\n').forEach(line => {
            const sub = line.trim();
            if (sub) allSubdomains.add(sub);
          });
          usedTool = usedTool ? `${usedTool}+amass` : 'amass';
        } catch (error: any) {
          logger.warn('Amass failed', error.message);
        }
      }

      const result: SubdomainResult = {
        domain,
        subdomains: Array.from(allSubdomains).sort(),
        tool: usedTool,
        count: allSubdomains.size,
        duration_ms: Date.now() - startTime,
      };

      this.auditLogger.logSuccess('enumerate-subdomains', domain, result.count, result.duration_ms);
      return result;
    } catch (error: any) {
      this.auditLogger.logFailure('enumerate-subdomains', domain, error.message);
      throw error;
    }
  }

  /**
   * 端口扫描
   */
  public async portScan(
    target: string,
    ports?: string,
    scanType: 'quick' | 'common' | 'full' = 'common'
  ): Promise<PortScanResult> {
    const startTime = Date.now();

    // 1. 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(target);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('port-scan', target, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 2. 频率限制
    const canProceed = await this.rateLimitManager.consume('port-scan', target);
    if (!canProceed) {
      throw new Error('Rate limit exceeded. Port scan is limited to 1 per 10 seconds.');
    }

    // 3. 确定端口范围
    let portRange: string;
    if (ports) {
      portRange = ports;
    } else {
      switch (scanType) {
        case 'quick':
          portRange = '--top-ports 100';
          break;
        case 'full':
          portRange = '-p-';
          break;
        case 'common':
        default:
          portRange = '--top-ports 1000';
      }
    }

    try {
      logger.info(`Running nmap on ${target} (${scanType})`);

      // 等待自适应延迟
      await this.adaptiveLimiter.wait();

      const nmapCmd = `nmap -Pn -T4 -sV ${portRange} ${target} -oX -`;
      const { stdout } = await execAsync(nmapCmd, { timeout: 600000 }); // 10 分钟超时

      // 解析 XML 输出
      const openPorts = this.parseNmapOutput(stdout);

      const result: PortScanResult = {
        target,
        open_ports: openPorts,
        tool: 'nmap',
        duration_ms: Date.now() - startTime,
      };

      this.adaptiveLimiter.recordSuccess();
      this.auditLogger.logSuccess('port-scan', target, openPorts.length, result.duration_ms);

      return result;
    } catch (error: any) {
      this.adaptiveLimiter.recordError();
      this.auditLogger.logFailure('port-scan', target, error.message);
      throw error;
    }
  }

  /**
   * 解析 nmap XML 输出
   */
  private parseNmapOutput(xml: string): Array<{
    port: number;
    protocol: string;
    service?: string;
    version?: string;
  }> {
    const ports: Array<{
      port: number;
      protocol: string;
      service?: string;
      version?: string;
    }> = [];

    try {
      const $ = cheerio.load(xml, { xmlMode: true });

      $('port').each((_, el) => {
        const state = $(el).find('state').attr('state');
        if (state === 'open') {
          const portId = parseInt($(el).attr('portid') || '0');
          const protocol = $(el).attr('protocol') || 'tcp';
          const service = $(el).find('service').attr('name');
          const version = $(el).find('service').attr('version');

          ports.push({
            port: portId,
            protocol,
            service,
            version,
          });
        }
      });
    } catch (error) {
      logger.warn('Failed to parse nmap output', error);
    }

    return ports;
  }

  /**
   * Web 指纹识别
   */
  public async webFingerprint(url: string, deep: boolean = false): Promise<FingerprintResult> {
    // 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(url);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('web-fingerprint', url, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 频率限制
    const canProceed = await this.rateLimitManager.consume('web-fingerprint', url);
    if (!canProceed) {
      throw new Error('Rate limit exceeded.');
    }

    try {
      logger.info(`Fingerprinting ${url}`);

      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        maxRedirects: 3,
      });

      const $ = cheerio.load(response.data);
      const technologies: Array<{ name: string; version?: string; categories?: string[] }> = [];

      // 检测服务器
      const server = response.headers['server'] as string | undefined;

      // 检测常见框架
      if (response.data.includes('wp-content')) {
        technologies.push({ name: 'WordPress', categories: ['CMS'] });
      }
      if (response.data.includes('Joomla')) {
        technologies.push({ name: 'Joomla', categories: ['CMS'] });
      }
      if ($('meta[name="generator"]').attr('content')?.includes('Drupal')) {
        technologies.push({ name: 'Drupal', categories: ['CMS'] });
      }

      // 检测 JavaScript 框架
      if (response.data.includes('react')) {
        technologies.push({ name: 'React', categories: ['JavaScript Framework'] });
      }
      if (response.data.includes('vue')) {
        technologies.push({ name: 'Vue.js', categories: ['JavaScript Framework'] });
      }
      if (response.data.includes('angular')) {
        technologies.push({ name: 'Angular', categories: ['JavaScript Framework'] });
      }

      // 提取标题
      const title = $('title').text().trim();

      const result: FingerprintResult = {
        url,
        status_code: response.status,
        technologies,
        server,
        headers: response.headers as Record<string, string>,
        title,
      };

      this.auditLogger.logSuccess('web-fingerprint', url, technologies.length);
      return result;
    } catch (error: any) {
      this.auditLogger.logFailure('web-fingerprint', url, error.message);
      throw error;
    }
  }

  /**
   * 提取 API 端点
   */
  public async extractEndpoints(url: string, depth: number = 2): Promise<EndpointResult> {
    // 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(url);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('extract-endpoints', url, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 频率限制
    const canProceed = await this.rateLimitManager.consume('extract-endpoints', url);
    if (!canProceed) {
      throw new Error('Rate limit exceeded.');
    }

    try {
      logger.info(`Extracting endpoints from ${url}`);

      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      });

      const $ = cheerio.load(response.data);
      const jsFiles: string[] = [];
      const endpoints: Array<{ path: string; method?: string; parameters?: string[] }> = [];

      // 提取 JS 文件
      $('script[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
          const absoluteUrl = new URL(src, url).href;
          jsFiles.push(absoluteUrl);
        }
      });

      // 从 JS 文件提取 API 端点（简化版）
      const apiPatterns = [
        /["'](\/api\/[^"']+)["']/g,
        /["'](\/v\d+\/[^"']+)["']/g,
        /fetch\(["']([^"']+)["']/g,
        /axios\.(get|post|put|delete)\(["']([^"']+)["']/g,
      ];

      for (const jsUrl of jsFiles.slice(0, 10)) {
        try {
          const jsResponse = await axios.get(jsUrl, { timeout: 5000 });
          const jsContent = jsResponse.data;

          for (const pattern of apiPatterns) {
            const matches = jsContent.matchAll(pattern);
            for (const match of matches) {
              const path = match[1] || match[2];
              if (path && path.startsWith('/')) {
                endpoints.push({ path });
              }
            }
          }
        } catch (error) {
          logger.debug(`Failed to fetch JS file: ${jsUrl}`);
        }
      }

      // 去重
      const uniqueEndpoints = Array.from(
        new Set(endpoints.map(e => e.path))
      ).map(path => ({ path }));

      const result: EndpointResult = {
        url,
        endpoints: uniqueEndpoints,
        js_files: jsFiles,
        api_patterns: uniqueEndpoints.map(e => e.path),
      };

      this.auditLogger.logSuccess('extract-endpoints', url, uniqueEndpoints.length);
      return result;
    } catch (error: any) {
      this.auditLogger.logFailure('extract-endpoints', url, error.message);
      throw error;
    }
  }

  /**
   * 目录扫描
   */
  public async directoryScan(
    url: string,
    wordlist?: string,
    extensions?: string[]
  ): Promise<DirectoryScanResult> {
    const startTime = Date.now();

    // 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(url);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('directory-scan', url, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 频率限制
    const canProceed = await this.rateLimitManager.consume('directory-scan', url);
    if (!canProceed) {
      throw new Error('Rate limit exceeded.');
    }

    try {
      logger.info(`Directory scanning ${url}`);

      // 构建 dirsearch 命令
      const wordlistArg = wordlist ? `-w ${wordlist}` : '';
      const extensionsArg = extensions ? `-e ${extensions.join(',')}` : '-e php,asp,aspx,jsp,html';

      const cmd = `dirsearch -u ${url} ${wordlistArg} ${extensionsArg} --quiet --format=json -o /tmp/dirsearch_output.json`;

      await execAsync(cmd, { timeout: 300000 });

      // 读取结果
      const outputPath = '/tmp/dirsearch_output.json';
      let found: Array<{ path: string; status: number; size?: number; redirect?: string }> = [];

      if (existsSync(outputPath)) {
        const content = readFileSync(outputPath, 'utf-8');
        const results = JSON.parse(content);

        found = results.results?.map((item: any) => ({
          path: item.path,
          status: item.status,
          size: item.content_length,
          redirect: item.redirect,
        })) || [];
      }

      const result: DirectoryScanResult = {
        url,
        found,
        wordlist: wordlist || 'built-in',
        duration_ms: Date.now() - startTime,
      };

      this.auditLogger.logSuccess('directory-scan', url, found.length, result.duration_ms);
      return result;
    } catch (error: any) {
      this.auditLogger.logFailure('directory-scan', url, error.message);
      throw error;
    }
  }
}
