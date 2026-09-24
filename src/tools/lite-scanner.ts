/**
 * 轻量级漏洞扫描器 - 无需 Nuclei
 * 使用内置 payload 库进行基础安全检测
 */

import { logger } from '../utils/logger.js';
import { httpClient } from '../utils/http-client.js';

export interface VulnerabilityResult {
  url: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  proof: string;
  remediation: string;
}

/**
 * SQL 注入检测（安全 payload）
 */
export async function detectSqlInjection(url: string): Promise<VulnerabilityResult[]> {
  const results: VulnerabilityResult[] = [];

  // 安全的测试 payload（不会造成实际危害）
  const payloads = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "1' ORDER BY 1--",
  ];

  for (const payload of payloads) {
    try {
      const testUrl = url.includes('?') ? `${url}&test=${payload}` : `${url}?test=${payload}`;
      const response = await httpClient.get(testUrl, { timeout: 5000 });

      // 检测常见 SQL 错误特征
      const errorSignatures = [
        'SQL syntax',
        'mysql_fetch',
        'PostgreSQL',
        'ORA-',
        'Microsoft SQL',
        'ODBC',
        'SQLite',
        'Unclosed quotation',
      ];

      for (const signature of errorSignatures) {
        if (response.data.includes(signature)) {
          results.push({
            url: testUrl,
            type: 'SQL Injection',
            severity: 'high',
            description: '检测到可能的 SQL 注入漏洞（基于错误回显）',
            proof: `Payload: ${payload}, 响应包含: ${signature}`,
            remediation: '使用参数化查询或 ORM，避免拼接 SQL 语句',
          });
          break;
        }
      }
    } catch (error) {
      // 跳过网络错误
      logger.debug(`SQL 注入测试失败: ${error}`);
    }
  }

  return results;
}

/**
 * XSS 检测（安全 payload）
 */
export async function detectXss(url: string): Promise<VulnerabilityResult[]> {
  const results: VulnerabilityResult[] = [];

  // 安全的测试 payload（使用 alert 的文本形式，不会实际执行）
  const payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
  ];

  for (const payload of payloads) {
    try {
      const testUrl = url.includes('?') ? `${url}&xss=${encodeURIComponent(payload)}` : `${url}?xss=${encodeURIComponent(payload)}`;
      const response = await httpClient.get(testUrl, { timeout: 5000 });

      // 检查 payload 是否未经过滤直接回显
      if (response.data.includes(payload)) {
        results.push({
          url: testUrl,
          type: 'XSS (Reflected)',
          severity: 'medium',
          description: '检测到可能的反射型 XSS 漏洞（输入未过滤）',
          proof: `Payload: ${payload} 直接回显在响应中`,
          remediation: '对用户输入进行 HTML 转义，使用 CSP 策略',
        });
      }
    } catch (error) {
      logger.debug(`XSS 测试失败: ${error}`);
    }
  }

  return results;
}

/**
 * 敏感文件/目录检测
 */
export async function detectSensitiveFiles(baseUrl: string): Promise<VulnerabilityResult[]> {
  const results: VulnerabilityResult[] = [];

  const sensitivePaths = [
    '/.git/config',
    '/.env',
    '/config.php',
    '/phpinfo.php',
    '/test.php',
    '/admin',
    '/phpmyadmin',
    '/backup.sql',
    '/db.sql',
    '/.DS_Store',
    '/web.config',
    '/.htaccess',
    '/robots.txt',
  ];

  for (const path of sensitivePaths) {
    try {
      const testUrl = baseUrl.replace(/\/$/, '') + path;
      const response = await httpClient.get(testUrl, { timeout: 5000 });

      if (response.status === 200 && response.data.length > 0) {
        const severity = path.includes('git') || path.includes('env') || path.includes('sql')
          ? 'critical'
          : 'medium';

        results.push({
          url: testUrl,
          type: 'Sensitive File Exposure',
          severity,
          description: `发现敏感文件/目录: ${path}`,
          proof: `HTTP ${response.status}, Content-Length: ${response.data.length}`,
          remediation: '删除敏感文件或配置访问控制',
        });
      }
    } catch (error) {
      // 跳过 404/403
    }
  }

  return results;
}

/**
 * 安全响应头检测
 */
export async function detectSecurityHeaders(url: string): Promise<VulnerabilityResult[]> {
  const results: VulnerabilityResult[] = [];

  try {
    const response = await httpClient.get(url, { timeout: 5000 });

    const headers = response.headers;
    const missingHeaders = [];

    // 检查关键安全响应头
    if (!headers['x-frame-options']) {
      missingHeaders.push('X-Frame-Options');
    }
    if (!headers['x-content-type-options']) {
      missingHeaders.push('X-Content-Type-Options');
    }
    if (!headers['strict-transport-security']) {
      missingHeaders.push('Strict-Transport-Security');
    }
    if (!headers['content-security-policy']) {
      missingHeaders.push('Content-Security-Policy');
    }

    if (missingHeaders.length > 0) {
      results.push({
        url,
        type: 'Missing Security Headers',
        severity: 'low',
        description: '缺少安全响应头',
        proof: `缺失的头: ${missingHeaders.join(', ')}`,
        remediation: '在服务器配置中添加安全响应头',
      });
    }

    // 检查敏感信息泄露
    if (headers['server']) {
      results.push({
        url,
        type: 'Information Disclosure',
        severity: 'low',
        description: '服务器信息泄露',
        proof: `Server: ${headers['server']}`,
        remediation: '隐藏或混淆服务器版本信息',
      });
    }
  } catch (error) {
    logger.error(`安全响应头检测失败: ${error}`);
  }

  return results;
}

/**
 * 完整漏洞扫描
 */
export async function scanVulnerabilities(url: string, options: {
  checkSql?: boolean;
  checkXss?: boolean;
  checkFiles?: boolean;
  checkHeaders?: boolean;
} = {}): Promise<VulnerabilityResult[]> {
  const results: VulnerabilityResult[] = [];

  // 默认全部检测
  const opts = {
    checkSql: true,
    checkXss: true,
    checkFiles: true,
    checkHeaders: true,
    ...options,
  };

  logger.info(`开始扫描: ${url}`);

  if (opts.checkSql) {
    const sqlResults = await detectSqlInjection(url);
    results.push(...sqlResults);
  }

  if (opts.checkXss) {
    const xssResults = await detectXss(url);
    results.push(...xssResults);
  }

  if (opts.checkFiles) {
    const fileResults = await detectSensitiveFiles(url);
    results.push(...fileResults);
  }

  if (opts.checkHeaders) {
    const headerResults = await detectSecurityHeaders(url);
    results.push(...headerResults);
  }

  logger.info(`扫描完成，发现 ${results.length} 个问题`);

  return results;
}
