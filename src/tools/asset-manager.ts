import { readFileSync, writeFileSync, existsSync } from 'fs';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { parse as parseYaml } from 'yaml';
import { AssetDatabase, SRCPlatform, PlatformConfig } from '../types.js';
import { logger } from '../utils/logger.js';

export class AssetManager {
  private assetsPath: string;
  private platformsConfigPath: string;
  private assetDatabase: AssetDatabase = {};
  private platformConfigs: PlatformConfig[] = [];

  constructor(assetsPath: string, platformsConfigPath: string) {
    this.assetsPath = assetsPath;
    this.platformsConfigPath = platformsConfigPath;
    this.loadAssets();
    this.loadPlatformConfigs();
  }

  private loadAssets(): void {
    try {
      if (existsSync(this.assetsPath)) {
        const content = readFileSync(this.assetsPath, 'utf-8');
        this.assetDatabase = JSON.parse(content);
        logger.info(`Assets loaded: ${Object.keys(this.assetDatabase).length} platforms`);
      } else {
        logger.warn('Assets database not found, initializing empty');
        this.assetDatabase = {};
      }
    } catch (error) {
      logger.error('Failed to load assets', error);
      this.assetDatabase = {};
    }
  }

  private loadPlatformConfigs(): void {
    try {
      if (existsSync(this.platformsConfigPath)) {
        const content = readFileSync(this.platformsConfigPath, 'utf-8');
        const config = parseYaml(content);
        this.platformConfigs = config.platforms || [];
        logger.info(`Platform configs loaded: ${this.platformConfigs.length}`);
      } else {
        logger.warn('Platform config not found');
        this.platformConfigs = [];
      }
    } catch (error) {
      logger.error('Failed to load platform configs', error);
      this.platformConfigs = [];
    }
  }

  /**
   * 同步 SRC 平台资产
   */
  public async syncAssets(
    platforms?: string[],
    force: boolean = false
  ): Promise<{ synced: number; total_assets: number; updated_at: string }> {
    const targetPlatforms = platforms
      ? this.platformConfigs.filter(p => platforms.includes(p.id))
      : this.platformConfigs;

    if (targetPlatforms.length === 0) {
      throw new Error('No platforms configured');
    }

    let synced = 0;
    const results: SRCPlatform[] = [];

    for (const config of targetPlatforms) {
      try {
        // 检查缓存
        const existing = this.assetDatabase[config.id];
        if (existing && !force) {
          const cacheAge = Date.now() - new Date(existing.updated_at).getTime();
          if (cacheAge < 24 * 60 * 60 * 1000) {
            // 缓存 < 24 小时
            logger.info(`Using cached data for ${config.id}`);
            results.push(existing);
            continue;
          }
        }

        logger.info(`Syncing ${config.name}...`);
        const platform = await this.scrapePlatform(config);

        if (platform) {
          this.assetDatabase[config.id] = platform;
          results.push(platform);
          synced++;
        }

        // 防止触发反爬
        await this.sleep(2000);
      } catch (error: any) {
        logger.error(`Failed to sync ${config.name}`, error);
      }
    }

    // 保存到文件
    if (synced > 0) {
      this.saveAssets();
    }

    // 统计总资产数
    const totalAssets = Object.values(this.assetDatabase).reduce(
      (sum, p) => sum + p.scope.domains.length + (p.scope.ips?.length || 0),
      0
    );

    return {
      synced,
      total_assets: totalAssets,
      updated_at: new Date().toISOString(),
    };
  }

  /**
   * 爬取单个平台
   */
  private async scrapePlatform(config: PlatformConfig): Promise<SRCPlatform | null> {
    try {
      const response = await axios.get(config.url, {
        timeout: 30000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      });

      const $ = cheerio.load(response.data);

      // 提取测试范围（需根据实际页面结构调整选择器）
      const domains: string[] = [];
      const ips: string[] = [];

      // 示例：从表格或列表提取域名
      if (config.selectors.scope) {
        $(config.selectors.scope).each((_, el) => {
          const text = $(el).text().trim();
          if (text.includes('*')) {
            domains.push(text);
          } else if (/^\d+\.\d+\.\d+\.\d+/.test(text)) {
            ips.push(text);
          }
        });
      }

      // 提取允许/禁止的漏洞类型
      const allowedTypes: any[] = [];
      const forbidden: string[] = [];

      if (config.selectors.rules) {
        $(config.selectors.rules).each((_, el) => {
          const text = $(el).text().trim();
          if (text.includes('允许') || text.includes('接受')) {
            allowedTypes.push(this.extractVulnType(text));
          } else if (text.includes('禁止') || text.includes('不接受')) {
            forbidden.push(this.extractVulnType(text));
          }
        });
      }

      if (domains.length === 0) {
        logger.warn(`No domains found for ${config.name}`);
        return null;
      }

      return {
        id: config.id,
        name: config.name,
        url: config.url,
        scope: {
          domains: [...new Set(domains)],
          ips: ips.length > 0 ? [...new Set(ips)] : undefined,
        },
        allowed_types: allowedTypes.filter(Boolean),
        forbidden: [...new Set(forbidden.filter(Boolean))],
        updated_at: new Date().toISOString(),
      };
    } catch (error: any) {
      logger.error(`Scraping failed for ${config.name}`, error.message);
      return null;
    }
  }

  /**
   * 从文本提取漏洞类型
   */
  private extractVulnType(text: string): string {
    const mapping: Record<string, string> = {
      'SQL注入': 'sql_injection',
      'XSS': 'xss',
      '跨站脚本': 'xss',
      'CSRF': 'csrf',
      '文件上传': 'file_upload',
      '命令执行': 'rce',
      'RCE': 'rce',
      'SSRF': 'ssrf',
      '越权': 'privilege_escalation',
      '逻辑漏洞': 'logic_flaw',
    };

    for (const [key, value] of Object.entries(mapping)) {
      if (text.includes(key)) {
        return value;
      }
    }

    return 'other';
  }

  /**
   * 搜索资产
   */
  public async searchAssets(keyword: string): Promise<{
    results: Array<{ platform: string; match: string; type: 'domain' | 'ip' }>;
    count: number;
  }> {
    const results: Array<{ platform: string; match: string; type: 'domain' | 'ip' }> = [];
    const lowerKeyword = keyword.toLowerCase();

    for (const [id, platform] of Object.entries(this.assetDatabase)) {
      // 搜索域名
      for (const domain of platform.scope.domains) {
        if (domain.toLowerCase().includes(lowerKeyword)) {
          results.push({
            platform: platform.name,
            match: domain,
            type: 'domain',
          });
        }
      }

      // 搜索 IP
      if (platform.scope.ips) {
        for (const ip of platform.scope.ips) {
          if (ip.includes(keyword)) {
            results.push({
              platform: platform.name,
              match: ip,
              type: 'ip',
            });
          }
        }
      }
    }

    return {
      results,
      count: results.length,
    };
  }

  /**
   * 保存资产库
   */
  private saveAssets(): void {
    try {
      writeFileSync(
        this.assetsPath,
        JSON.stringify(this.assetDatabase, null, 2),
        'utf-8'
      );
      logger.info('Assets saved successfully');
    } catch (error) {
      logger.error('Failed to save assets', error);
    }
  }

  /**
   * 重新加载
   */
  public async reload(): Promise<void> {
    this.loadAssets();
    this.loadPlatformConfigs();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
