# SRC Hunter 快速开始

## 🚀 5 分钟上手指南

### Step 1: 验证安装

重启 Claude Code 后，MCP Server 应该已自动加载。验证：

```bash
# 在 Claude Code 中询问
"列出可用的 MCP 工具"
```

你应该看到 `src-hunter` 相关的工具。

### Step 2: 授权目标域名

**所有操作前必须先授权！**

```typescript
authorize-target {
  "target": "example.com",
  "scope": "full"
}
```

**作用域说明**：
- `subdomain`：仅允许子域名枚举
- `full`：允许完整侦察和扫描
- `read-only`：只读模式（安全）

### Step 3: 开始侦察

#### 3.1 子域名枚举

```typescript
enumerate-subdomains-lite { "domain": "example.com" }
```

**返回示例**：
```json
[
  "www.example.com",
  "api.example.com",
  "mail.example.com",
  "blog.example.com"
]
```

#### 3.2 Web 指纹识别

```typescript
web-fingerprint-lite { "url": "https://example.com" }
```

**返回示例**：
```json
{
  "url": "https://example.com",
  "status": 200,
  "title": "Example Domain",
  "server": "nginx/1.21.0",
  "technologies": ["React", "Bootstrap"],
  "headers": {
    "content-type": "text/html",
    "x-powered-by": "Express"
  }
}
```

#### 3.3 端口扫描

```typescript
port-scan-lite {
  "host": "example.com",
  "ports": [80, 443, 8080, 8443, 3000, 3001, 8000, 8888]
}
```

**返回示例**：
```json
[
  { "port": 80, "open": true },
  { "port": 443, "open": true },
  { "port": 8080, "open": false }
]
```

#### 3.4 提取 API 端点

```typescript
extract-endpoints-lite { "url": "https://example.com" }
```

**返回示例**：
```json
[
  "/api/users",
  "/api/posts",
  "/api/auth/login",
  "/graphql"
]
```

### Step 4: 漏洞扫描

```typescript
vuln-scan-lite {
  "url": "https://example.com",
  "check_sql": true,
  "check_xss": true,
  "check_files": true,
  "check_headers": true
}
```

**返回示例**：
```json
[
  {
    "type": "missing_security_header",
    "severity": "low",
    "description": "缺少 X-Frame-Options 头"
  },
  {
    "type": "xss_reflected",
    "severity": "high",
    "url": "https://example.com/search?q=<script>",
    "description": "可能存在反射型 XSS"
  }
]
```

### Step 5: 查看审计日志

```typescript
get-audit-log { "limit": 20 }
```

## 📋 完整工作流示例

### 场景：侦察一个新目标

```typescript
// 1. 授权目标
authorize-target { "target": "example.com", "scope": "full" }

// 2. 子域名枚举
enumerate-subdomains-lite { "domain": "example.com" }
// 结果：发现 api.example.com, admin.example.com

// 3. 逐个指纹识别
web-fingerprint-lite { "url": "https://api.example.com" }
web-fingerprint-lite { "url": "https://admin.example.com" }

// 4. 端口扫描
port-scan-lite { 
  "host": "api.example.com",
  "ports": [80, 443, 8080, 8443]
}

// 5. 提取 API 端点
extract-endpoints-lite { "url": "https://api.example.com" }

// 6. 漏洞扫描
vuln-scan-lite {
  "url": "https://api.example.com",
  "check_sql": true,
  "check_xss": true,
  "check_files": true,
  "check_headers": true
}

// 7. 查看审计日志
get-audit-log { "limit": 50 }

// 8. 完成后撤销授权
revoke-authorization { "target": "example.com" }
```

## 🎯 常见使用场景

### 场景 1：快速资产发现

```typescript
// 目标：快速找出公司所有子域名和开放端口
authorize-target { "target": "company.com", "scope": "subdomain" }
enumerate-subdomains-lite { "domain": "company.com" }

// 对每个子域名扫描常用端口
port-scan-lite { "host": "sub1.company.com", "ports": [80, 443, 8080, 8443, 3000] }
```

### 场景 2：Web 应用安全检查

```typescript
// 目标：检查 Web 应用的基础安全配置
authorize-target { "target": "webapp.com", "scope": "read-only" }

// 1. 指纹识别
web-fingerprint-lite { "url": "https://webapp.com" }

// 2. 安全头检查
vuln-scan-lite {
  "url": "https://webapp.com",
  "check_headers": true
}
```

### 场景 3：API 端点映射

```typescript
// 目标：找出所有 API 端点
authorize-target { "target": "api.example.com", "scope": "read-only" }

// 1. 提取端点
extract-endpoints-lite { "url": "https://api.example.com" }

// 2. 测试常见漏洞
vuln-scan-lite {
  "url": "https://api.example.com/api/users",
  "check_sql": true,
  "check_xss": true
}
```

## ⚠️ 注意事项

### 1. 授权要求

- ❌ **未授权扫描是违法的**
- ✅ 仅扫描你有权限测试的目标
- ✅ 使用公开的漏洞赏金平台（HackerOne, Bugcrowd）
- ✅ 获得书面授权后再进行测试

### 2. 速率限制

- crt.sh API 有速率限制（~每分钟 10 次请求）
- 端口扫描不要过于频繁（可能被 WAF 封禁）
- 建议使用缓存避免重复请求

### 3. 误报

- 轻量版工具可能产生误报
- 建议手动验证所有发现
- 高危漏洞需要人工确认

## 🔍 故障排除

### 问题 1：工具无响应

```bash
# 检查 MCP Server 是否运行
# 在 Claude Code 中查看状态
"MCP 服务器状态"
```

### 问题 2：授权失败

```typescript
// 确保目标格式正确
authorize-target { "target": "example.com", "scope": "full" }

// 不要包含协议
// ❌ https://example.com
// ✅ example.com
```

### 问题 3：crt.sh 超时

```typescript
// crt.sh 可能暂时不可用，稍后重试
// 或安装外部工具（Subfinder）
```

## 📚 下一步

- 阅读 [完整文档](README.md)
- 安装 [外部工具](docs/TOOL-INSTALLATION.md)（更强大）
- 学习 [API 参考](docs/API-REFERENCE.md)
- 查看 [架构设计](docs/SRC-HUNTER-DESIGN.md)

---

**遇到问题？** 查看审计日志获取详细错误信息：

```typescript
get-audit-log { "limit": 100 }
```
