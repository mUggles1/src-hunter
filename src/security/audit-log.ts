import { appendFileSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { AuditLog, AuditLogSchema } from '../types.js';
import { logger } from '../utils/logger.js';

export class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
    this.ensureLogDirectory();
  }

  private ensureLogDirectory(): void {
    const dir = dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * 记录审计日志
   */
  public log(entry: Omit<AuditLog, 'timestamp'>): void {
    try {
      const fullEntry: AuditLog = {
        timestamp: new Date().toISOString(),
        ...entry,
      };

      // 验证日志格式
      const validated = AuditLogSchema.parse(fullEntry);

      // 写入日志文件（JSON Lines 格式）
      const logLine = JSON.stringify(validated) + '\n';
      appendFileSync(this.logPath, logLine, 'utf-8');

      // 同时写入应用日志
      const logMessage = `[AUDIT] ${validated.tool} on ${validated.target}: ${validated.result}`;
      if (validated.result === 'success') {
        logger.info(logMessage, { findings: validated.findings_count });
      } else if (validated.result === 'blocked') {
        logger.warn(logMessage, { reason: validated.reason });
      } else {
        logger.error(logMessage, { reason: validated.reason });
      }
    } catch (error) {
      logger.error('Failed to write audit log', error);
    }
  }

  /**
   * 记录成功的扫描
   */
  public logSuccess(
    tool: string,
    target: string,
    findingsCount: number = 0,
    durationMs?: number,
    user?: string
  ): void {
    this.log({
      tool,
      target,
      user,
      result: 'success',
      findings_count: findingsCount,
      duration_ms: durationMs,
    });
  }

  /**
   * 记录失败的扫描
   */
  public logFailure(
    tool: string,
    target: string,
    reason: string,
    user?: string
  ): void {
    this.log({
      tool,
      target,
      user,
      result: 'failed',
      reason,
    });
  }

  /**
   * 记录被阻止的请求
   */
  public logBlocked(
    tool: string,
    target: string,
    reason: string,
    user?: string
  ): void {
    this.log({
      tool,
      target,
      user,
      result: 'blocked',
      reason,
    });
  }

  /**
   * 批量记录（用于工作流）
   */
  public logBatch(entries: Omit<AuditLog, 'timestamp'>[]): void {
    for (const entry of entries) {
      this.log(entry);
    }
  }
}

/**
 * 安全事件监控器
 */
export class SecurityMonitor {
  private auditLogger: AuditLogger;
  private alertThresholds: {
    blockedRequestsPerMinute: number;
    failedRequestsPerMinute: number;
  };
  private recentEvents: Map<string, number[]>; // tool -> timestamps

  constructor(
    auditLogger: AuditLogger,
    alertThresholds = {
      blockedRequestsPerMinute: 10,
      failedRequestsPerMinute: 20,
    }
  ) {
    this.auditLogger = auditLogger;
    this.alertThresholds = alertThresholds;
    this.recentEvents = new Map();

    // 每分钟清理旧事件
    setInterval(() => this.cleanOldEvents(), 60000);
  }

  /**
   * 记录事件并检查异常
   */
  public recordEvent(tool: string, result: 'success' | 'failed' | 'blocked'): void {
    const now = Date.now();
    const events = this.recentEvents.get(tool) || [];
    events.push(now);
    this.recentEvents.set(tool, events);

    // 检查异常模式
    this.checkAnomalies(tool, result);
  }

  /**
   * 检查异常行为
   */
  private checkAnomalies(tool: string, result: 'success' | 'failed' | 'blocked'): void {
    const events = this.recentEvents.get(tool) || [];
    const oneMinuteAgo = Date.now() - 60000;
    const recentCount = events.filter(ts => ts > oneMinuteAgo).length;

    if (result === 'blocked' && recentCount > this.alertThresholds.blockedRequestsPerMinute) {
      logger.warn(`⚠️ SECURITY ALERT: High blocked request rate for ${tool} (${recentCount}/min)`);
      // 可扩展：发送告警通知
    }

    if (result === 'failed' && recentCount > this.alertThresholds.failedRequestsPerMinute) {
      logger.warn(`⚠️ ALERT: High failure rate for ${tool} (${recentCount}/min)`);
    }
  }

  /**
   * 清理 1 分钟前的事件
   */
  private cleanOldEvents(): void {
    const oneMinuteAgo = Date.now() - 60000;

    for (const [tool, events] of this.recentEvents.entries()) {
      const filtered = events.filter(ts => ts > oneMinuteAgo);
      if (filtered.length === 0) {
        this.recentEvents.delete(tool);
      } else {
        this.recentEvents.set(tool, filtered);
      }
    }
  }

  /**
   * 获取最近的事件统计
   */
  public getStats(): Record<string, { total: number; blocked: number; failed: number }> {
    const stats: Record<string, { total: number; blocked: number; failed: number }> = {};

    for (const [tool, events] of this.recentEvents.entries()) {
      const oneMinuteAgo = Date.now() - 60000;
      const recentEvents = events.filter(ts => ts > oneMinuteAgo);

      stats[tool] = {
        total: recentEvents.length,
        blocked: 0, // 需要从日志中统计
        failed: 0,
      };
    }

    return stats;
  }
}

/**
 * Payload 安全检查器
 */
export class PayloadValidator {
  private static FORBIDDEN_PATTERNS = [
    // 文件操作
    /rm\s+-rf/i,
    /del\s+\/[fs]/i,
    /rmdir\s+\/s/i,

    // SQL 破坏
    /DROP\s+(TABLE|DATABASE)/i,
    /DELETE\s+FROM.*WHERE\s+1=1/i,
    /TRUNCATE\s+TABLE/i,

    // XSS 攻击
    /<script>alert\(/i,
    /javascript:eval\(/i,
    /onerror\s*=\s*['"]?alert/i,

    // 命令注入
    /;\s*(cat|ls|whoami|id|uname)/i,
    /\|\s*(curl|wget|nc|bash)/i,
    /`[^`]*`/,
    /\$\([^)]*\)/,

    // XXE
    /<!ENTITY.*SYSTEM/i,
    /<!DOCTYPE.*\[/i,

    // SSRF
    /file:\/\//i,
    /dict:\/\//i,
    /gopher:\/\//i,

    // 密码爆破
    /admin['\"]?\s*:\s*['"]?(admin|password|123456)/i,
  ];

  /**
   * 检查 payload 是否安全
   */
  public static validate(payload: string): { safe: boolean; reason?: string } {
    for (const pattern of this.FORBIDDEN_PATTERNS) {
      if (pattern.test(payload)) {
        return {
          safe: false,
          reason: `Forbidden pattern detected: ${pattern.source}`,
        };
      }
    }

    return { safe: true };
  }

  /**
   * 批量检查
   */
  public static validateBatch(payloads: string[]): Map<string, boolean> {
    const results = new Map<string, boolean>();
    for (const payload of payloads) {
      results.set(payload, this.validate(payload).safe);
    }
    return results;
  }

  /**
   * 获取安全的 payload 变体
   */
  public static getSafeVariant(payload: string): string {
    // 替换危险操作为安全探测
    let safe = payload;

    // SQL 注入：使用 sleep 而非破坏性操作
    safe = safe.replace(/DROP\s+TABLE/gi, 'SELECT SLEEP(1)');
    safe = safe.replace(/DELETE\s+FROM/gi, 'SELECT 1 FROM');

    // XSS：使用无害的 alert
    safe = safe.replace(/alert\(['"]?.*?['"]?\)/gi, 'alert(1)');

    // 命令注入：使用 echo 而非实际命令
    safe = safe.replace(/;\s*(cat|ls|whoami)/gi, '; echo test');

    return safe;
  }
}
