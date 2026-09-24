# SRC Hunter MCP Server

**轻量版漏洞赏金猎人工具链** - 无需外部工具，纯 Node.js 实现

## 🎯 特性

### ✅ 已实现（无需外部工具）

- **子域名枚举**：crt.sh API（免费、快速）
- **Web 指纹识别**：技术栈检测、服务器信息
- **API 端点提取**：从 HTML/JS 中提取 URL
- **端口扫描**：TCP 连接测试（常用端口）
- **漏洞扫描**：SQL 注入、XSS、文件遍历、安全头检查
- **授权检查**：域名白名单、操作审计日志

### 🔧 可选（需安装外部工具）

- Subfinder/Amass：高级子域名枚举
- Nmap：全面端口扫描
- Nuclei：漏洞模板引擎
- Dirsearch：目录爆破

## 📦 安装

### 1. 安装依赖

```bash
cd C:\Users\Q\.claude\mcp-servers\src-hunter
npm install
npm run build
```

### 2. 配置 Claude Code

已自动添加到 `C:\Users\Q\.claude\mcp.json`：

```json
{
  "mcpServers": {
    "src-hunter": {
      "command": "node",
      "args": ["C:\\Users\\Q\\.claude\\mcp-servers\\src-hunter\\build\\index.js"],
      "description": "SRC Hunter: 漏洞赏金猎人工具链"
    }
  }
}
```

### 3. 重启 Claude Code

关闭并重新打开 Claude Code，MCP Server 将自动加载。

## 🚀 使用方法

### 授权管理

```typescript
// 添加授权域名
authorize-target { "target": "example.com", "scope": "subdomain" }

// 查看授权列表
list-authorizations {}

// 撤销授权
revoke-authorization { "target": "example.com" }
```

### 侦察工具（轻量版）

```typescript
// 子域名枚举（使用 crt.sh）
enumerate-subdomains-lite { "domain": "example.com" }

// Web 指纹识别
web-fingerprint-lite { "url": "https://example.com" }

// 提取 API 端点
extract-endpoints-lite { "url": "https://example.com" }

// 端口扫描
port-scan-lite { 
  "host": "example.com",
  "ports": [80, 443, 8080, 8443, 3000]
}
```

### 漏洞扫描（轻量版）

```typescript
vuln-scan-lite {
  "url": "https://example.com",
  "check_sql": true,
  "check_xss": true,
  "check_files": true,
  "check_headers": true
}
```

### 查看审计日志

```typescript
get-audit-log { "limit": 50 }
```

## 📊 工具对比

| 功能 | 轻量版 | 外部工具版 |
|------|--------|-----------|
| 子域名枚举 | crt.sh API | Subfinder + Amass |
| 端口扫描 | TCP 连接 | Nmap 全功能 |
| Web 指纹 | 基础检测 | httpx 深度扫描 |
| 漏洞扫描 | 常见漏洞 | Nuclei 5000+ 模板 |
| 安装难度 | ✅ 零依赖 | ⚠️ 需配置工具 |
| 速度 | 🚀 快速 | 🐢 较慢但全面 |

## 🔒 安全机制

### 1. 域名授权

所有操作必须先授权目标域名：

```typescript
authorize-target { "target": "example.com", "scope": "full" }
```

作用域：
- `subdomain`：仅子域名
- `full`：完整扫描
- `read-only`：只读侦察

### 2. 审计日志

所有操作自动记录：
- 时间戳
- 操作类型
- 目标
- 结果统计
- 执行时长

日志位置：`src-hunter-audit.log`

### 3. 安全限制

- 禁止扫描未授权域名
- 端口扫描限制在常用端口
- 漏洞扫描使用安全 payload

## 🛠️ 故障排除

### MCP Server 未加载

```bash
# 检查编译是否成功
ls C:\Users\Q\.claude\mcp-servers\src-hunter\build\index.js

# 查看 Claude Code 日志
# 文件 → 偏好设置 → 开发者工具
```

### 工具无响应

```bash
# 测试 Node.js 环境
node --version  # 应该 >= 18

# 重新构建
npm run build
```

### crt.sh API 限流

crt.sh 有速率限制，建议：
- 增加请求间隔
- 使用缓存结果
- 切换到外部工具版（Subfinder）

## 📚 进阶配置

### 安装外部工具（可选）

如需更强大功能，运行：

```powershell
# PowerShell 管理员模式
cd C:\Users\Q\.claude\mcp-servers\src-hunter\scripts
.\download-prebuilt-tools.ps1
```

这将安装：
- Subfinder v2.6.6
- httpx v1.6.8
- Nuclei v3.3.8

详见：[docs/TOOL-INSTALLATION.md](docs/TOOL-INSTALLATION.md)

## 📖 相关文档

- [SRC Hunter 架构设计](docs/SRC-HUNTER-DESIGN.md)
- [工具安装指南](docs/TOOL-INSTALLATION.md)
- [无 Go 环境替代方案](docs/NO-GO-ALTERNATIVE.md)
- [API 参考](docs/API-REFERENCE.md)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License
