/**
 * 统一 HTTP 客户端
 * 使用浏览器 User-Agent 绕过基础 WAF/CDN 拦截
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';

// 浏览器 User-Agent 列表（随机轮换，降低被拦截概率）
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
];

// 常用浏览器请求头
const BROWSER_HEADERS: Record<string, string> = {
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
  'Accept-Encoding': 'gzip, deflate, br',
  'Cache-Control': 'no-cache',
  'Pragma': 'no-cache',
  'Connection': 'keep-alive',
  'Upgrade-Insecure-Requests': '1',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
};

/**
 * 获取随机 User-Agent
 */
export function getRandomUserAgent(): string {
  const index = Math.floor(Math.random() * USER_AGENTS.length);
  return USER_AGENTS[index];
}

/**
 * 创建带浏览器头的 axios 实例
 */
export function createHttpClient(options?: AxiosRequestConfig): AxiosInstance {
  return axios.create({
    timeout: 15000,
    maxRedirects: 5,
    validateStatus: () => true, // 接受所有状态码（包括 403/404）
    headers: {
      ...BROWSER_HEADERS,
      'User-Agent': getRandomUserAgent(),
    },
    ...options,
  });
}

// 默认客户端实例（复用连接池）
export const httpClient = createHttpClient();
