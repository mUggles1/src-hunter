import { RateLimiterMemory } from 'rate-limiter-flexible';
import { logger } from '../utils/logger.js';

interface RateLimitConfig {
  points: number;      // 允许的请求次数
  duration: number;    // 时间窗口（秒）
  blockDuration?: number; // 超限后阻塞时间（秒）
}

const DEFAULT_LIMITS: Record<string, RateLimitConfig> = {
  'port-scan': { points: 1, duration: 10, blockDuration: 60 },
  'vuln-scan': { points: 1, duration: 60, blockDuration: 300 },
  'directory-scan': { points: 1, duration: 30, blockDuration: 120 },
  'enumerate-subdomains': { points: 1, duration: 30, blockDuration: 120 },
  'web-fingerprint': { points: 5, duration: 60 },
  'extract-endpoints': { points: 3, duration: 60 },
  'default': { points: 10, duration: 60 },
};

export class RateLimitManager {
  private limiters: Map<string, RateLimiterMemory>;

  constructor(customLimits?: Record<string, RateLimitConfig>) {
    this.limiters = new Map();
    const limits = { ...DEFAULT_LIMITS, ...customLimits };

    // 为每个工具创建限流器
    for (const [tool, config] of Object.entries(limits)) {
      this.limiters.set(tool, new RateLimiterMemory({
        points: config.points,
        duration: config.duration,
        blockDuration: config.blockDuration,
      }));
    }

    logger.info('Rate limiter initialized');
  }

  /**
   * 消费一个请求令牌
   * @returns true 如果允许，false 如果超限
   */
  public async consume(tool: string, key: string = 'global'): Promise<boolean> {
    const limiter = this.limiters.get(tool) || this.limiters.get('default')!;
    const rateLimitKey = `${tool}:${key}`;

    try {
      await limiter.consume(rateLimitKey);
      return true;
    } catch (error: any) {
      if (error.msBeforeNext) {
        const waitSeconds = Math.ceil(error.msBeforeNext / 1000);
        logger.warn(`Rate limit exceeded for ${tool}. Wait ${waitSeconds}s`);
      }
      return false;
    }
  }

  /**
   * 检查是否可以执行（不消费令牌）
   */
  public async check(tool: string, key: string = 'global'): Promise<{
    allowed: boolean;
    remainingPoints?: number;
    msBeforeNext?: number;
  }> {
    const limiter = this.limiters.get(tool) || this.limiters.get('default')!;
    const rateLimitKey = `${tool}:${key}`;

    try {
      const res = await limiter.get(rateLimitKey);
      if (!res) {
        return { allowed: true };
      }

      const limiterOptions = limiter as any;
      const pointsConsumed = res.consumedPoints;
      const pointsLimit = limiterOptions.points;

      if (pointsConsumed < pointsLimit) {
        return {
          allowed: true,
          remainingPoints: pointsLimit - pointsConsumed,
        };
      }

      const msBeforeReset = res.msBeforeNext || 0;
      return {
        allowed: false,
        msBeforeNext: msBeforeReset,
      };
    } catch (error) {
      logger.error('Rate limit check failed', error);
      return { allowed: true }; // Fail open
    }
  }

  /**
   * 重置指定工具的限流状态
   */
  public async reset(tool: string, key: string = 'global'): Promise<void> {
    const limiter = this.limiters.get(tool) || this.limiters.get('default')!;
    const rateLimitKey = `${tool}:${key}`;

    try {
      await limiter.delete(rateLimitKey);
      logger.info(`Rate limit reset for ${tool}:${key}`);
    } catch (error) {
      logger.error('Rate limit reset failed', error);
    }
  }

  /**
   * 获取所有工具的限流配置
   */
  public getLimits(): Record<string, { points: number; duration: number }> {
    const limits: Record<string, { points: number; duration: number }> = {};

    for (const [tool, limiter] of this.limiters.entries()) {
      const opts = limiter as any;
      limits[tool] = {
        points: opts.points,
        duration: opts.duration,
      };
    }

    return limits;
  }

  /**
   * 批量检查多个目标的限流状态
   */
  public async checkBatch(
    tool: string,
    keys: string[]
  ): Promise<Map<string, boolean>> {
    const results = new Map<string, boolean>();

    await Promise.all(
      keys.map(async (key) => {
        const { allowed } = await this.check(tool, key);
        results.set(key, allowed);
      })
    );

    return results;
  }
}

/**
 * 自适应限流器：根据目标响应动态调整速率
 */
export class AdaptiveRateLimiter {
  private baseDelayMs: number;
  private maxDelayMs: number;
  private currentDelayMs: number;
  private errorCount: number;
  private successCount: number;

  constructor(baseDelayMs: number = 1000, maxDelayMs: number = 10000) {
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.currentDelayMs = baseDelayMs;
    this.errorCount = 0;
    this.successCount = 0;
  }

  /**
   * 等待（自适应延迟）
   */
  public async wait(): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, this.currentDelayMs));
  }

  /**
   * 记录成功请求
   */
  public recordSuccess(): void {
    this.successCount++;
    this.errorCount = 0;

    // 连续成功 5 次，减少延迟
    if (this.successCount >= 5) {
      this.currentDelayMs = Math.max(
        this.baseDelayMs,
        this.currentDelayMs * 0.8
      );
      this.successCount = 0;
      logger.debug(`Adaptive rate: decreased to ${this.currentDelayMs}ms`);
    }
  }

  /**
   * 记录失败请求（429/503/WAF 等）
   */
  public recordError(): void {
    this.errorCount++;
    this.successCount = 0;

    // 指数退避
    this.currentDelayMs = Math.min(
      this.maxDelayMs,
      this.currentDelayMs * Math.pow(2, this.errorCount)
    );
    logger.warn(`Adaptive rate: increased to ${this.currentDelayMs}ms (errors: ${this.errorCount})`);
  }

  /**
   * 重置计数器
   */
  public reset(): void {
    this.currentDelayMs = this.baseDelayMs;
    this.errorCount = 0;
    this.successCount = 0;
  }

  /**
   * 获取当前延迟
   */
  public getCurrentDelay(): number {
    return this.currentDelayMs;
  }
}
