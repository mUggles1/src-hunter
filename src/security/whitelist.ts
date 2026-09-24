import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import CIDRMatcher from 'cidr-matcher';
import { Whitelist, WhitelistSchema, AuthorizationResult, AssetDatabase } from '../types.js';
import { logger } from '../utils/logger.js';

export class WhitelistManager {
  private whitelist!: Whitelist;
  private assetDatabase: AssetDatabase = {};
  private cidrMatcher: CIDRMatcher;
  private whitelistPath: string;
  private assetsPath: string;

  constructor(whitelistPath: string, assetsPath: string) {
    this.whitelistPath = whitelistPath;
    this.assetsPath = assetsPath;
    this.cidrMatcher = new CIDRMatcher([]);
    this.loadWhitelist();
    this.loadAssets();
  }

  private loadWhitelist(): void {
    try {
      if (!existsSync(this.whitelistPath)) {
        logger.warn(`Whitelist file not found: ${this.whitelistPath}`);
        this.whitelist = { authorized_targets: [], src_platforms: [] };
        return;
      }

      const content = readFileSync(this.whitelistPath, 'utf-8');
      const parsed = JSON.parse(content);
      this.whitelist = WhitelistSchema.parse(parsed);

      // 提取 IP/CIDR
      const cidrs = this.whitelist.authorized_targets.filter(
        target => target.includes('/') || /^\d+\.\d+\.\d+\.\d+$/.test(target)
      );
      if (cidrs.length > 0) {
        this.cidrMatcher = new CIDRMatcher(cidrs);
      }

      logger.info(`Whitelist loaded: ${this.whitelist.authorized_targets.length} targets`);
    } catch (error) {
      logger.error('Failed to load whitelist', error);
      throw new Error('Whitelist initialization failed');
    }
  }

  private loadAssets(): void {
    try {
      if (!existsSync(this.assetsPath)) {
        logger.warn(`Assets database not found: ${this.assetsPath}`);
        return;
      }

      const content = readFileSync(this.assetsPath, 'utf-8');
      this.assetDatabase = JSON.parse(content);
      logger.info(`Assets database loaded: ${Object.keys(this.assetDatabase).length} platforms`);
    } catch (error) {
      logger.error('Failed to load assets database', error);
    }
  }

  /**
   * 检查目标是否授权
   */
  public checkAuthorization(target: string): AuthorizationResult {
    // 1. 规范化目标
    const normalized = this.normalizeTarget(target);

    // 2. 检查白名单中的域名通配符
    for (const pattern of this.whitelist.authorized_targets) {
      if (this.matchPattern(normalized.domain, pattern)) {
        return {
          authorized: true,
          matched_pattern: pattern,
          reason: 'Matched whitelist pattern',
        };
      }
    }

    // 3. 检查 IP/CIDR
    if (normalized.ip && this.cidrMatcher.contains(normalized.ip)) {
      return {
        authorized: true,
        matched_pattern: normalized.ip,
        reason: 'Matched CIDR range',
      };
    }

    // 4. 检查 SRC 平台资产库
    for (const [platformId, platform] of Object.entries(this.assetDatabase)) {
      // 检查域名范围
      for (const scopeDomain of platform.scope.domains) {
        if (this.matchPattern(normalized.domain, scopeDomain)) {
          return {
            authorized: true,
            platform: platform.name,
            matched_pattern: scopeDomain,
            reason: `Authorized by ${platform.name}`,
          };
        }
      }

      // 检查 IP 范围
      if (normalized.ip && platform.scope.ips) {
        for (const scopeIp of platform.scope.ips) {
          if (scopeIp.includes('/')) {
            const matcher = new CIDRMatcher([scopeIp]);
            if (matcher.contains(normalized.ip)) {
              return {
                authorized: true,
                platform: platform.name,
                matched_pattern: scopeIp,
                reason: `Authorized by ${platform.name}`,
              };
            }
          } else if (normalized.ip === scopeIp) {
            return {
              authorized: true,
              platform: platform.name,
              matched_pattern: scopeIp,
              reason: `Authorized by ${platform.name}`,
            };
          }
        }
      }
    }

    // 5. 未授权
    return {
      authorized: false,
      reason: 'Target not in whitelist or SRC scope',
    };
  }

  /**
   * 规范化目标（提取域名/IP）
   */
  private normalizeTarget(target: string): { domain: string; ip?: string } {
    // 移除协议
    let normalized = target.replace(/^https?:\/\//, '');

    // 移除路径和参数
    normalized = normalized.split('/')[0].split('?')[0];

    // 移除端口
    normalized = normalized.split(':')[0];

    // 判断是 IP 还是域名
    const ipPattern = /^\d+\.\d+\.\d+\.\d+$/;
    if (ipPattern.test(normalized)) {
      return { domain: normalized, ip: normalized };
    }

    return { domain: normalized };
  }

  /**
   * 通配符匹配
   * 支持：*.example.com, example.*, *example*
   */
  private matchPattern(domain: string, pattern: string): boolean {
    if (pattern === domain) return true;
    if (pattern === '*') return true;

    // 转换为正则表达式
    const regexPattern = pattern
      .replace(/\./g, '\\.')
      .replace(/\*/g, '.*');

    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(domain);
  }

  /**
   * 重新加载配置
   */
  public reload(): void {
    this.loadWhitelist();
    this.loadAssets();
  }

  /**
   * 获取所有授权目标
   */
  public getAuthorizedTargets(): string[] {
    const targets = [...this.whitelist.authorized_targets];

    // 添加 SRC 资产库中的目标
    for (const platform of Object.values(this.assetDatabase)) {
      targets.push(...platform.scope.domains);
      if (platform.scope.ips) {
        targets.push(...platform.scope.ips);
      }
    }

    return [...new Set(targets)];
  }

  /**
   * 获取指定平台的授权范围
   */
  public getPlatformScope(platformId: string): string[] | null {
    const platform = this.assetDatabase[platformId];
    if (!platform) return null;

    const scope = [...platform.scope.domains];
    if (platform.scope.ips) {
      scope.push(...platform.scope.ips);
    }
    return scope;
  }

  /**
   * 检查漏洞类型是否允许测试
   */
  public isVulnTypeAllowed(target: string, vulnType: string): boolean {
    const normalized = this.normalizeTarget(target);

    // 查找匹配的平台
    for (const platform of Object.values(this.assetDatabase)) {
      for (const scopeDomain of platform.scope.domains) {
        if (this.matchPattern(normalized.domain, scopeDomain)) {
          // 检查是否在禁止列表中
          const forbidden = platform.forbidden.some(item =>
            item.toLowerCase().includes(vulnType.toLowerCase())
          );
          if (forbidden) return false;

          // 检查是否在允许列表中（如果有的话）
          if (platform.allowed_types.length > 0) {
            return platform.allowed_types.some(type =>
              type.toLowerCase().includes(vulnType.toLowerCase())
            );
          }

          return true;
        }
      }
    }

    // 默认允许（如果在白名单中）
    return true;
  }
}
