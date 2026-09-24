import { z } from 'zod';

// ==================== 基础类型 ====================

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof SeveritySchema>;

export const VulnTypeSchema = z.enum([
  'sql_injection',
  'xss',
  'csrf',
  'rce',
  'ssrf',
  'file_upload',
  'path_traversal',
  'xxe',
  'auth_bypass',
  'privilege_escalation',
  'logic_flaw',
  'info_disclosure',
  'other'
]);
export type VulnType = z.infer<typeof VulnTypeSchema>;

// ==================== SRC 平台 ====================

export const SRCPlatformSchema = z.object({
  id: z.string(),
  name: z.string(),
  url: z.string().url(),
  scope: z.object({
    domains: z.array(z.string()),
    ips: z.array(z.string()).optional(),
    apps: z.array(z.string()).optional(),
  }),
  allowed_types: z.array(VulnTypeSchema),
  forbidden: z.array(z.string()),
  updated_at: z.string(),
  notes: z.string().optional(),
});
export type SRCPlatform = z.infer<typeof SRCPlatformSchema>;

export const AssetDatabaseSchema = z.record(z.string(), SRCPlatformSchema);
export type AssetDatabase = z.infer<typeof AssetDatabaseSchema>;

// ==================== 授权检查 ====================

export const WhitelistSchema = z.object({
  authorized_targets: z.array(z.string()),
  src_platforms: z.array(z.string()),
  notes: z.string().optional(),
});
export type Whitelist = z.infer<typeof WhitelistSchema>;

export interface AuthorizationResult {
  authorized: boolean;
  platform?: string;
  reason?: string;
  matched_pattern?: string;
}

// ==================== 侦察结果 ====================

export const SubdomainResultSchema = z.object({
  domain: z.string(),
  subdomains: z.array(z.string()),
  tool: z.string(),
  count: z.number(),
  duration_ms: z.number(),
});
export type SubdomainResult = z.infer<typeof SubdomainResultSchema>;

export const PortScanResultSchema = z.object({
  target: z.string(),
  open_ports: z.array(z.object({
    port: z.number(),
    protocol: z.string(),
    service: z.string().optional(),
    version: z.string().optional(),
  })),
  tool: z.string(),
  duration_ms: z.number(),
});
export type PortScanResult = z.infer<typeof PortScanResultSchema>;

export const FingerprintResultSchema = z.object({
  url: z.string(),
  status_code: z.number(),
  technologies: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
    categories: z.array(z.string()).optional(),
  })),
  server: z.string().optional(),
  headers: z.record(z.string()).optional(),
  title: z.string().optional(),
});
export type FingerprintResult = z.infer<typeof FingerprintResultSchema>;

export const EndpointResultSchema = z.object({
  url: z.string(),
  endpoints: z.array(z.object({
    path: z.string(),
    method: z.string().optional(),
    parameters: z.array(z.string()).optional(),
  })),
  js_files: z.array(z.string()),
  api_patterns: z.array(z.string()),
});
export type EndpointResult = z.infer<typeof EndpointResultSchema>;

export const DirectoryScanResultSchema = z.object({
  url: z.string(),
  found: z.array(z.object({
    path: z.string(),
    status: z.number(),
    size: z.number().optional(),
    redirect: z.string().optional(),
  })),
  wordlist: z.string(),
  duration_ms: z.number(),
});
export type DirectoryScanResult = z.infer<typeof DirectoryScanResultSchema>;

// ==================== 漏洞扫描 ====================

export const FindingSchema = z.object({
  id: z.string(),
  severity: SeveritySchema,
  type: VulnTypeSchema,
  name: z.string(),
  url: z.string(),
  method: z.string().optional(),
  parameter: z.string().optional(),
  payload: z.string().optional(),
  evidence: z.string(),
  description: z.string().optional(),
  confidence: z.number().min(0).max(1),
  verified: z.boolean().default(false),
  cve: z.string().optional(),
  reference: z.array(z.string()).optional(),
  created_at: z.string(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const VulnScanResultSchema = z.object({
  scan_id: z.string(),
  target: z.string(),
  start_time: z.string(),
  end_time: z.string().optional(),
  status: z.enum(['running', 'completed', 'failed', 'aborted']),
  findings: z.array(FindingSchema),
  stats: z.object({
    total: z.number(),
    critical: z.number(),
    high: z.number(),
    medium: z.number(),
    low: z.number(),
    info: z.number(),
  }),
  tools_used: z.array(z.string()),
});
export type VulnScanResult = z.infer<typeof VulnScanResultSchema>;

// ==================== 完整扫描报告 ====================

export const ReconReportSchema = z.object({
  scan_id: z.string(),
  target: z.string(),
  start_time: z.string(),
  end_time: z.string(),
  authorization: z.object({
    authorized: z.boolean(),
    platform: z.string().optional(),
  }),
  recon: z.object({
    subdomains: SubdomainResultSchema.optional(),
    ports: PortScanResultSchema.optional(),
    fingerprint: FingerprintResultSchema.optional(),
    endpoints: EndpointResultSchema.optional(),
    directories: DirectoryScanResultSchema.optional(),
  }),
  vuln_scan: VulnScanResultSchema.optional(),
  summary: z.string(),
});
export type ReconReport = z.infer<typeof ReconReportSchema>;

// ==================== 审计日志 ====================

export const AuditLogSchema = z.object({
  timestamp: z.string(),
  tool: z.string(),
  target: z.string(),
  user: z.string().optional(),
  result: z.enum(['success', 'failed', 'blocked']),
  reason: z.string().optional(),
  findings_count: z.number().optional(),
  duration_ms: z.number().optional(),
});
export type AuditLog = z.infer<typeof AuditLogSchema>;

// ==================== 工具配置 ====================

export interface ToolConfig {
  enabled: boolean;
  path?: string;
  args?: string[];
  timeout_ms?: number;
  rate_limit?: string;
}

export interface SecurityConfig {
  whitelist_path: string;
  audit_log_path: string;
  max_requests_per_minute: number;
  forbidden_payloads: string[];
  safe_mode: boolean;
}

export interface PlatformConfig {
  id: string;
  name: string;
  url: string;
  selectors: {
    scope?: string;
    rules?: string;
    forbidden?: string;
  };
}

// ==================== MCP 工具参数 ====================

export const SyncAssetsParamsSchema = z.object({
  platforms: z.array(z.string()).optional(),
  force: z.boolean().optional(),
});

export const CheckAuthorizationParamsSchema = z.object({
  target: z.string(),
});

export const EnumerateSubdomainsParamsSchema = z.object({
  domain: z.string(),
  tools: z.array(z.string()).optional(),
  timeout_ms: z.number().optional(),
});

export const PortScanParamsSchema = z.object({
  target: z.string(),
  ports: z.string().optional(),
  scan_type: z.enum(['quick', 'common', 'full']).optional(),
});

export const WebFingerprintParamsSchema = z.object({
  url: z.string().url(),
  deep: z.boolean().optional(),
});

export const ExtractEndpointsParamsSchema = z.object({
  url: z.string().url(),
  depth: z.number().optional(),
});

export const DirectoryScanParamsSchema = z.object({
  url: z.string().url(),
  wordlist: z.string().optional(),
  extensions: z.array(z.string()).optional(),
});

export const VulnScanParamsSchema = z.object({
  target: z.string(),
  severity: z.array(SeveritySchema).optional(),
  templates: z.array(z.string()).optional(),
  safe_mode: z.boolean().optional(),
});

export const VerifyCVEParamsSchema = z.object({
  target: z.string(),
  cve: z.string(),
  safe_mode: z.boolean().optional(),
});

export const GenerateReportParamsSchema = z.object({
  scan_id: z.string(),
  format: z.enum(['md', 'json', 'html']).optional(),
  include_raw: z.boolean().optional(),
});
