import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'fs';
import { resolve } from 'path';
import { randomBytes } from 'crypto';
import {
  VulnScanResult,
  Finding,
  Severity,
  VulnType,
  ReconReport,
} from '../types.js';
import { WhitelistManager } from '../security/whitelist.js';
import { RateLimitManager, AdaptiveRateLimiter } from '../security/rate-limit.js';
import { AuditLogger, PayloadValidator } from '../security/audit-log.js';
import { logger } from '../utils/logger.js';

const execAsync = promisify(exec);

export class ScannerTools {
  private whitelistManager: WhitelistManager;
  private rateLimitManager: RateLimitManager;
  private auditLogger: AuditLogger;
  private adaptiveLimiter: AdaptiveRateLimiter;
  private scansDir: string;

  constructor(
    whitelistManager: WhitelistManager,
    rateLimitManager: RateLimitManager,
    auditLogger: AuditLogger
  ) {
    this.whitelistManager = whitelistManager;
    this.rateLimitManager = rateLimitManager;
    this.auditLogger = auditLogger;
    this.adaptiveLimiter = new AdaptiveRateLimiter(2000, 15000);
    this.scansDir = resolve(process.cwd(), 'data', 'scans');

    // 确保扫描目录存在
    if (!existsSync(this.scansDir)) {
      mkdirSync(this.scansDir, { recursive: true });
    }
  }

  /**
   * 综合漏洞扫描
   */
  public async vulnScan(
    target: string,
    severity?: Severity[],
    templates?: string[],
    safeMode: boolean = true
  ): Promise<VulnScanResult> {
    const startTime = Date.now();
    const scanId = `scan_${Date.now()}_${randomBytes(4).toString('hex')}`;

    // 1. 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(target);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('vuln-scan', target, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 2. 频率限制
    const canProceed = await this.rateLimitManager.consume('vuln-scan', target);
    if (!canProceed) {
      throw new Error('Rate limit exceeded. Vuln scan is limited to 1 per minute.');
    }

    // 3. 构建 nuclei 命令
    const severityArg = severity?.length
      ? `-severity ${severity.join(',')}`
      : '-severity critical,high,medium';

    const templatesArg = templates?.length
      ? `-t ${templates.join(',')}`
      : '-t cves/ -t vulnerabilities/';

    const outputPath = resolve(this.scansDir, `${scanId}.json`);

    try {
      logger.info(`Starting vuln scan on ${target} (safe_mode: ${safeMode})`);

      // 等待自适应延迟
      await this.adaptiveLimiter.wait();

      // 安全模式：添加额外限制
      const safeModeArgs = safeMode
        ? '-rate-limit 10 -timeout 10'
        : '-rate-limit 50';

      const nucleiCmd = `nuclei -u ${target} ${severityArg} ${templatesArg} ${safeModeArgs} -jsonl -o ${outputPath} -silent`;

      await execAsync(nucleiCmd, { timeout: 600000 }); // 10 分钟超时

      // 解析结果
      const findings = this.parseNucleiOutput(outputPath, target);

      // 统计
      const stats = {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length,
      };

      const result: VulnScanResult = {
        scan_id: scanId,
        target,
        start_time: new Date(startTime).toISOString(),
        end_time: new Date().toISOString(),
        status: 'completed',
        findings,
        stats,
        tools_used: ['nuclei'],
      };

      // 保存完整结果
      this.saveScanResult(scanId, result);

      this.adaptiveLimiter.recordSuccess();
      this.auditLogger.logSuccess('vuln-scan', target, findings.length, Date.now() - startTime);

      return result;
    } catch (error: any) {
      this.adaptiveLimiter.recordError();
      this.auditLogger.logFailure('vuln-scan', target, error.message);

      const result: VulnScanResult = {
        scan_id: scanId,
        target,
        start_time: new Date(startTime).toISOString(),
        status: 'failed',
        findings: [],
        stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        tools_used: ['nuclei'],
      };

      this.saveScanResult(scanId, result);
      throw error;
    }
  }

  /**
   * 解析 nuclei JSONL 输出
   */
  private parseNucleiOutput(outputPath: string, target: string): Finding[] {
    const findings: Finding[] = [];

    if (!existsSync(outputPath)) {
      return findings;
    }

    try {
      const content = readFileSync(outputPath, 'utf-8');
      const lines = content.split('\n').filter(line => line.trim());

      for (const line of lines) {
        try {
          const result = JSON.parse(line);

          // 提取漏洞类型
          const vulnType = this.mapToVulnType(result.info?.tags || []);

          const finding: Finding = {
            id: `${result.templateID}_${Date.now()}`,
            severity: (result.info?.severity || 'info') as Severity,
            type: vulnType,
            name: result.info?.name || result.templateID,
            url: result.matched || target,
            method: result.type?.toUpperCase(),
            evidence: result.matched_line || result.extracted_results?.join(', ') || '',
            description: result.info?.description,
            confidence: this.calculateConfidence(result),
            verified: false,
            cve: result.info?.classification?.['cve-id'],
            reference: result.info?.reference,
            created_at: new Date().toISOString(),
          };

          findings.push(finding);
        } catch (parseError) {
          logger.warn('Failed to parse nuclei result line', parseError);
        }
      }
    } catch (error) {
      logger.error('Failed to parse nuclei output', error);
    }

    return findings;
  }

  /**
   * 映射到标准漏洞类型
   */
  private mapToVulnType(tags: string[]): VulnType {
    const tagStr = tags.join(',').toLowerCase();

    if (tagStr.includes('sqli') || tagStr.includes('sql-injection')) return 'sql_injection';
    if (tagStr.includes('xss')) return 'xss';
    if (tagStr.includes('csrf')) return 'csrf';
    if (tagStr.includes('rce') || tagStr.includes('code-execution')) return 'rce';
    if (tagStr.includes('ssrf')) return 'ssrf';
    if (tagStr.includes('upload')) return 'file_upload';
    if (tagStr.includes('traversal') || tagStr.includes('lfi')) return 'path_traversal';
    if (tagStr.includes('xxe')) return 'xxe';
    if (tagStr.includes('auth')) return 'auth_bypass';
    if (tagStr.includes('privilege')) return 'privilege_escalation';
    if (tagStr.includes('disclosure')) return 'info_disclosure';

    return 'other';
  }

  /**
   * 计算置信度
   */
  private calculateConfidence(result: any): number {
    let confidence = 0.5;

    // CVE 漏洞置信度较高
    if (result.info?.classification?.['cve-id']) {
      confidence += 0.3;
    }

    // 有提取结果置信度更高
    if (result.extracted_results?.length > 0) {
      confidence += 0.2;
    }

    // 高严重等级置信度更高
    if (result.info?.severity === 'critical' || result.info?.severity === 'high') {
      confidence += 0.1;
    }

    return Math.min(confidence, 1.0);
  }

  /**
   * 验证特定 CVE
   */
  public async verifyCVE(
    target: string,
    cve: string,
    safeMode: boolean = true
  ): Promise<Finding | null> {
    // 授权检查
    const authCheck = this.whitelistManager.checkAuthorization(target);
    if (!authCheck.authorized) {
      this.auditLogger.logBlocked('verify-cve', target, authCheck.reason!);
      throw new Error(`Unauthorized target: ${authCheck.reason}`);
    }

    // 频率限制
    const canProceed = await this.rateLimitManager.consume('vuln-scan', target);
    if (!canProceed) {
      throw new Error('Rate limit exceeded.');
    }

    try {
      logger.info(`Verifying ${cve} on ${target}`);

      // 查找对应的 nuclei 模板
      const outputPath = resolve(this.scansDir, `verify_${cve}_${Date.now()}.json`);
      const nucleiCmd = `nuclei -u ${target} -t cves/ -tags ${cve} -jsonl -o ${outputPath} -silent`;

      await execAsync(nucleiCmd, { timeout: 60000 });

      // 解析结果
      const findings = this.parseNucleiOutput(outputPath, target);

      if (findings.length > 0) {
        const finding = findings[0];
        finding.verified = true;
        this.auditLogger.logSuccess('verify-cve', target, 1);
        return finding;
      }

      this.auditLogger.logSuccess('verify-cve', target, 0);
      return null;
    } catch (error: any) {
      this.auditLogger.logFailure('verify-cve', target, error.message);
      throw error;
    }
  }

  /**
   * 生成报告
   */
  public async generateReport(
    scanId: string,
    format: 'md' | 'json' | 'html' = 'md',
    includeRaw: boolean = false
  ): Promise<{ content: string; path: string }> {
    const scanPath = resolve(this.scansDir, `${scanId}.json`);

    if (!existsSync(scanPath)) {
      throw new Error(`Scan not found: ${scanId}`);
    }

    const scanResult: VulnScanResult = JSON.parse(readFileSync(scanPath, 'utf-8'));

    let content: string;
    let filename: string;

    switch (format) {
      case 'json':
        content = JSON.stringify(scanResult, null, 2);
        filename = `${scanId}_report.json`;
        break;

      case 'html':
        content = this.generateHTMLReport(scanResult);
        filename = `${scanId}_report.html`;
        break;

      case 'md':
      default:
        content = this.generateMarkdownReport(scanResult);
        filename = `${scanId}_report.md`;
        break;
    }

    const reportPath = resolve(this.scansDir, filename);
    writeFileSync(reportPath, content, 'utf-8');

    logger.info(`Report generated: ${reportPath}`);

    return {
      content,
      path: reportPath,
    };
  }

  /**
   * 生成 Markdown 报告
   */
  private generateMarkdownReport(scan: VulnScanResult): string {
    const lines: string[] = [];

    lines.push(`# 漏洞扫描报告`);
    lines.push('');
    lines.push(`**扫描 ID**: ${scan.scan_id}`);
    lines.push(`**目标**: ${scan.target}`);
    lines.push(`**开始时间**: ${scan.start_time}`);
    lines.push(`**结束时间**: ${scan.end_time || 'N/A'}`);
    lines.push(`**状态**: ${scan.status}`);
    lines.push('');

    lines.push(`## 统计`);
    lines.push('');
    lines.push(`| 严重等级 | 数量 |`);
    lines.push(`|---------|------|`);
    lines.push(`| 🔴 Critical | ${scan.stats.critical} |`);
    lines.push(`| 🟠 High | ${scan.stats.high} |`);
    lines.push(`| 🟡 Medium | ${scan.stats.medium} |`);
    lines.push(`| 🟢 Low | ${scan.stats.low} |`);
    lines.push(`| ℹ️ Info | ${scan.stats.info} |`);
    lines.push(`| **总计** | **${scan.stats.total}** |`);
    lines.push('');

    if (scan.findings.length > 0) {
      lines.push(`## 漏洞详情`);
      lines.push('');

      // 按严重程度排序
      const sortedFindings = [...scan.findings].sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });

      for (const finding of sortedFindings) {
        const emoji = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🟢',
          info: 'ℹ️',
        }[finding.severity];

        lines.push(`### ${emoji} ${finding.name}`);
        lines.push('');
        lines.push(`- **严重等级**: ${finding.severity.toUpperCase()}`);
        lines.push(`- **类型**: ${finding.type}`);
        lines.push(`- **URL**: ${finding.url}`);
        if (finding.method) lines.push(`- **方法**: ${finding.method}`);
        if (finding.parameter) lines.push(`- **参数**: ${finding.parameter}`);
        if (finding.cve) lines.push(`- **CVE**: ${finding.cve}`);
        lines.push(`- **置信度**: ${(finding.confidence * 100).toFixed(0)}%`);
        lines.push(`- **已验证**: ${finding.verified ? '✅' : '❌'}`);
        lines.push('');

        if (finding.description) {
          lines.push(`**描述**: ${finding.description}`);
          lines.push('');
        }

        lines.push(`**证据**:`);
        lines.push('```');
        lines.push(finding.evidence);
        lines.push('```');
        lines.push('');

        if (finding.reference) {
          lines.push(`**参考**:`);
          for (const ref of finding.reference) {
            lines.push(`- ${ref}`);
          }
          lines.push('');
        }

        lines.push('---');
        lines.push('');
      }
    }

    lines.push(`## 工具`);
    lines.push('');
    lines.push(`使用的工具: ${scan.tools_used.join(', ')}`);
    lines.push('');

    lines.push(`---`);
    lines.push(`*报告生成时间: ${new Date().toISOString()}*`);

    return lines.join('\n');
  }

  /**
   * 生成 HTML 报告（简化版）
   */
  private generateHTMLReport(scan: VulnScanResult): string {
    const mdContent = this.generateMarkdownReport(scan);
    // 这里可以集成 markdown-to-html 库
    // 暂时返回包装在 <pre> 中的 markdown
    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Scan Report - ${scan.scan_id}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    pre { background: #f4f4f4; padding: 15px; border-radius: 5px; }
  </style>
</head>
<body>
  <pre>${mdContent}</pre>
</body>
</html>
    `.trim();
  }

  /**
   * 导出发现（用于提交 SRC）
   */
  public async exportFindings(scanId: string): Promise<{
    findings: Finding[];
    export_path: string;
  }> {
    const scanPath = resolve(this.scansDir, `${scanId}.json`);

    if (!existsSync(scanPath)) {
      throw new Error(`Scan not found: ${scanId}`);
    }

    const scanResult: VulnScanResult = JSON.parse(readFileSync(scanPath, 'utf-8'));

    // 只导出 high 和 critical 级别的漏洞
    const criticalFindings = scanResult.findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );

    const exportPath = resolve(this.scansDir, `${scanId}_export.json`);
    writeFileSync(exportPath, JSON.stringify(criticalFindings, null, 2), 'utf-8');

    logger.info(`Findings exported: ${exportPath}`);

    return {
      findings: criticalFindings,
      export_path: exportPath,
    };
  }

  /**
   * 保存扫描结果
   */
  private saveScanResult(scanId: string, result: VulnScanResult): void {
    const path = resolve(this.scansDir, `${scanId}.json`);
    writeFileSync(path, JSON.stringify(result, null, 2), 'utf-8');
  }
}
