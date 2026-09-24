#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { resolve } from 'path';
import { existsSync, mkdirSync } from 'fs';

import { logger } from './utils/logger.js';
import { WhitelistManager } from './security/whitelist.js';
import { RateLimitManager } from './security/rate-limit.js';
import { AuditLogger, SecurityMonitor } from './security/audit-log.js';

// 工具实现
import { AssetManager } from './tools/asset-manager.js';
import { ReconTools } from './tools/recon.js';
import { ScannerTools } from './tools/scanner.js';

// 轻量版工具（无需外部依赖）
import * as LiteRecon from './tools/lite-recon.js';
import * as LiteScanner from './tools/lite-scanner.js';

// 初始化路径
const DATA_DIR = resolve(process.cwd(), 'data');
const CONFIG_DIR = resolve(process.cwd(), 'config');
const LOGS_DIR = resolve(process.cwd(), 'logs');

// 确保目录存在
for (const dir of [DATA_DIR, CONFIG_DIR, LOGS_DIR]) {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

// 安全组件
const whitelistManager = new WhitelistManager(
  resolve(DATA_DIR, 'whitelist.json'),
  resolve(DATA_DIR, 'assets.json')
);

const rateLimitManager = new RateLimitManager();
const auditLogger = new AuditLogger(resolve(DATA_DIR, 'audit.log'));
const securityMonitor = new SecurityMonitor(auditLogger);

// 业务组件
const assetManager = new AssetManager(
  resolve(DATA_DIR, 'assets.json'),
  resolve(CONFIG_DIR, 'platforms.yaml')
);

const reconTools = new ReconTools(
  whitelistManager,
  rateLimitManager,
  auditLogger
);

const scannerTools = new ScannerTools(
  whitelistManager,
  rateLimitManager,
  auditLogger
);

// 创建 MCP Server
const server = new Server(
  {
    name: 'src-hunter',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// ==================== 工具定义 ====================

const TOOLS: Tool[] = [
  // 资产管理
  {
    name: 'sync-src-assets',
    description: '同步 SRC 平台的授权测试范围（爬取最新资产信息）',
    inputSchema: {
      type: 'object',
      properties: {
        platforms: {
          type: 'array',
          items: { type: 'string' },
          description: '要同步的平台列表（不指定则同步全部）',
        },
        force: {
          type: 'boolean',
          description: '强制刷新（忽略缓存）',
        },
      },
    },
  },
  {
    name: 'search-assets',
    description: '搜索可测试的资产（域名/IP/APP）',
    inputSchema: {
      type: 'object',
      properties: {
        keyword: {
          type: 'string',
          description: '搜索关键词（支持模糊匹配）',
        },
      },
      required: ['keyword'],
    },
  },
  {
    name: 'check-authorization',
    description: '检查目标是否在授权测试范围内',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: '目标（域名/URL/IP）',
        },
      },
      required: ['target'],
    },
  },

  // 侦察工具（轻量版 - 优先使用）
  {
    name: 'enumerate-subdomains-lite',
    description: '子域名枚举（使用 crt.sh API，无需外部工具）',
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          description: '主域名（如 example.com）',
        },
      },
      required: ['domain'],
    },
  },
  {
    name: 'web-fingerprint-lite',
    description: 'Web 指纹识别（纯 Node.js 实现）',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标 URL',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'extract-endpoints-lite',
    description: '提取 API 端点（无需外部工具）',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标 URL',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'port-scan-lite',
    description: '简单端口扫描（TCP 连接测试）',
    inputSchema: {
      type: 'object',
      properties: {
        host: {
          type: 'string',
          description: '目标主机',
        },
        ports: {
          type: 'array',
          items: { type: 'number' },
          description: '端口列表（如 [80, 443, 8080]）',
        },
      },
      required: ['host', 'ports'],
    },
  },

  // 侦察工具（需要外部工具）
  {
    name: 'enumerate-subdomains',
    description: '子域名枚举（使用 subfinder + amass）',
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          type: 'string',
          description: '主域名（如 example.com）',
        },
        tools: {
          type: 'array',
          items: { type: 'string', enum: ['subfinder', 'amass', 'all'] },
          description: '使用的工具（默认 all）',
        },
        timeout_ms: {
          type: 'number',
          description: '超时时间（毫秒）',
        },
      },
      required: ['domain'],
    },
  },
  {
    name: 'port-scan',
    description: '端口扫描（使用 nmap）',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: '目标（域名/IP）',
        },
        ports: {
          type: 'string',
          description: '端口范围（如 "1-1000" 或 "80,443,8080"）',
        },
        scan_type: {
          type: 'string',
          enum: ['quick', 'common', 'full'],
          description: 'quick=top100, common=top1000, full=1-65535',
        },
      },
      required: ['target'],
    },
  },
  {
    name: 'web-fingerprint',
    description: 'Web 指纹识别（技术栈检测）',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标 URL',
        },
        deep: {
          type: 'boolean',
          description: '深度扫描（检测更多特征）',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'extract-endpoints',
    description: '提取 API 端点（从 JS 文件分析）',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标网站 URL',
        },
        depth: {
          type: 'number',
          description: '爬取深度（默认 2）',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'directory-scan',
    description: '敏感目录扫描',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标 URL',
        },
        wordlist: {
          type: 'string',
          description: '字典文件路径（不指定则使用内置字典）',
        },
        extensions: {
          type: 'array',
          items: { type: 'string' },
          description: '文件扩展名（如 ["php", "asp", "jsp"]）',
        },
      },
      required: ['url'],
    },
  },

  // 漏洞扫描（轻量版 - 无需外部工具）
  {
    name: 'vuln-scan-lite',
    description: '轻量级漏洞扫描（内置 payload，无需外部工具）',
    inputSchema: {
      type: 'object',
      properties: {
        url: {
          type: 'string',
          description: '目标 URL',
        },
        check_sql: {
          type: 'boolean',
          description: '检测 SQL 注入（默认 true）',
        },
        check_xss: {
          type: 'boolean',
          description: '检测 XSS（默认 true）',
        },
        check_files: {
          type: 'boolean',
          description: '检测敏感文件（默认 true）',
        },
        check_headers: {
          type: 'boolean',
          description: '检测安全响应头（默认 true）',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'verify-cve',
    description: '验证特定 CVE 漏洞',
    inputSchema: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: '目标 URL',
        },
        cve: {
          type: 'string',
          description: 'CVE 编号（如 CVE-2021-44228）',
        },
        safe_mode: {
          type: 'boolean',
          description: '安全模式',
        },
      },
      required: ['target', 'cve'],
    },
  },

  // 报告生成
  {
    name: 'generate-report',
    description: '生成侦察报告',
    inputSchema: {
      type: 'object',
      properties: {
        scan_id: {
          type: 'string',
          description: '扫描 ID',
        },
        format: {
          type: 'string',
          enum: ['md', 'json', 'html'],
          description: '报告格式',
        },
        include_raw: {
          type: 'boolean',
          description: '包含原始数据',
        },
      },
      required: ['scan_id'],
    },
  },
  {
    name: 'export-findings',
    description: '导出漏洞发现（用于提交 SRC）',
    inputSchema: {
      type: 'object',
      properties: {
        scan_id: {
          type: 'string',
          description: '扫描 ID',
        },
      },
      required: ['scan_id'],
    },
  },

  // 系统工具
  {
    name: 'get-rate-limits',
    description: '获取当前的限流配置',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'reload-config',
    description: '重新加载配置（白名单/资产库）',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

// ==================== 请求处理 ====================

server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.debug('Listing tools');
  return { tools: TOOLS };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const startTime = Date.now();

  logger.info(`Tool called: ${name}`, { args });

  try {
    let result: any;
    const toolArgs = args as any || {};

    switch (name) {
      // 资产管理
      case 'sync-src-assets':
        result = await assetManager.syncAssets(toolArgs.platforms, toolArgs.force);
        auditLogger.logSuccess(name, 'multiple', result.synced, Date.now() - startTime);
        break;

      case 'search-assets':
        result = await assetManager.searchAssets(toolArgs.keyword);
        break;

      case 'check-authorization':
        result = whitelistManager.checkAuthorization(toolArgs.target);
        if (!result.authorized) {
          auditLogger.logBlocked(name, toolArgs.target, result.reason || 'Not authorized');
        }
        break;

      // 轻量版侦察工具（优先使用）
      case 'enumerate-subdomains-lite':
        result = await LiteRecon.enumerateSubdomainsCrtSh(toolArgs.domain);
        auditLogger.logSuccess(name, toolArgs.domain, result.length, Date.now() - startTime);
        break;

      case 'web-fingerprint-lite':
        result = await LiteRecon.fingerprintWeb(toolArgs.url);
        auditLogger.logSuccess(name, toolArgs.url, 1, Date.now() - startTime);
        break;

      case 'extract-endpoints-lite':
        result = await LiteRecon.extractApiEndpoints(toolArgs.url);
        auditLogger.logSuccess(name, toolArgs.url, result.length, Date.now() - startTime);
        break;

      case 'port-scan-lite':
        result = await LiteRecon.scanPorts(toolArgs.host, toolArgs.ports);
        auditLogger.logSuccess(name, toolArgs.host, result.length, Date.now() - startTime);
        break;

      // 轻量版漏洞扫描
      case 'vuln-scan-lite':
        result = await LiteScanner.scanVulnerabilities(toolArgs.url, {
          checkSql: toolArgs.check_sql,
          checkXss: toolArgs.check_xss,
          checkFiles: toolArgs.check_files,
          checkHeaders: toolArgs.check_headers,
        });
        auditLogger.logSuccess(name, toolArgs.url, result.length, Date.now() - startTime);
        break;

      // 外部工具（需要安装）
      case 'enumerate-subdomains':
        result = await reconTools.enumerateSubdomains(
          toolArgs.domain,
          toolArgs.tools,
          toolArgs.timeout_ms
        );
        break;

      case 'port-scan':
        result = await reconTools.portScan(toolArgs.target, toolArgs.ports, toolArgs.scan_type);
        break;

      case 'web-fingerprint':
        result = await reconTools.webFingerprint(toolArgs.url, toolArgs.deep);
        break;

      case 'extract-endpoints':
        result = await reconTools.extractEndpoints(toolArgs.url, toolArgs.depth);
        break;

      case 'directory-scan':
        result = await reconTools.directoryScan(toolArgs.url, toolArgs.wordlist, toolArgs.extensions);
        break;

      // 漏洞扫描（需要 Nuclei）
      case 'vuln-scan':
        result = await scannerTools.vulnScan(
          toolArgs.target,
          toolArgs.severity,
          toolArgs.templates,
          toolArgs.safe_mode
        );
        break;

      case 'verify-cve':
        result = await scannerTools.verifyCVE(toolArgs.target, toolArgs.cve, toolArgs.safe_mode);
        break;

      // 报告
      case 'generate-report':
        result = await scannerTools.generateReport(
          toolArgs.scan_id,
          toolArgs.format,
          toolArgs.include_raw
        );
        break;

      case 'export-findings':
        result = await scannerTools.exportFindings(toolArgs.scan_id);
        break;

      // 系统工具
      case 'get-rate-limits':
        result = rateLimitManager.getLimits();
        break;

      case 'reload-config':
        whitelistManager.reload();
        await assetManager.reload();
        result = { success: true, message: 'Configuration reloaded' };
        break;

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    // 记录成功
    securityMonitor.recordEvent(name, 'success');

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    logger.error(`Tool execution failed: ${name}`, error);

    // 记录失败
    const toolArgs = args as any || {};
    auditLogger.logFailure(name, toolArgs.target || 'unknown', error.message);
    securityMonitor.recordEvent(name, 'failed');

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: error.message,
            tool: name,
            timestamp: new Date().toISOString(),
          }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// ==================== 启动服务器 ====================

async function main() {
  logger.info('Starting SRC Hunter MCP Server...');
  logger.info(`Data directory: ${DATA_DIR}`);
  logger.info(`Config directory: ${CONFIG_DIR}`);

  // 检查必需文件
  const requiredFiles = [
    resolve(DATA_DIR, 'whitelist.json'),
    resolve(CONFIG_DIR, 'platforms.yaml'),
  ];

  for (const file of requiredFiles) {
    if (!existsSync(file)) {
      logger.warn(`Required file missing: ${file}`);
      logger.warn('Please create this file before running scans');
    }
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info('SRC Hunter MCP Server started successfully');
  logger.info(`Registered tools: ${TOOLS.length}`);
}

main().catch((error) => {
  logger.error('Fatal error', error);
  process.exit(1);
});
