# SRC Hunter MCP Server - 安装指南

## 📋 前置要求

### 1. Node.js 环境
```bash
# 检查版本（需要 >= 18.0.0）
node --version
npm --version
```

### 2. 安全工具安装

#### Windows (推荐使用 WSL2 或原生 Windows 版本)

**子域名枚举工具**
```bash
# 安装 Go（如果没有）
# 下载：https://go.dev/dl/

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master
```

**Web 扫描工具**
```bash
# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新 Nuclei 模板
nuclei -update-templates
```

**端口扫描**
```bash
# Nmap - 下载安装包
# https://nmap.org/download.html
```

**目录扫描**
```bash
# Python + dirsearch
pip install dirsearch
```

**验证安装**
```bash
# 检查所有工具是否可用
subfinder -version
amass -version
httpx -version
nuclei -version
nmap --version
dirsearch --version
```

## 🚀 快速开始

### Step 1: 初始化项目
```bash
cd C:\Users\Q\.claude\mcp-servers\src-hunter
npm install
```

### Step 2: 编译 TypeScript
```bash
npm run build
```

### Step 3: 配置白名单
编辑 `data/whitelist.json`，添加授权目标：
```json
{
  "authorized_targets": [
    "*.your-authorized-domain.com",
    "test.example.com"
  ],
  "src_platforms": [
    "360SRC"
  ]
}
```

### Step 4: 注册到 Claude Code
编辑 `~/.claude/config/settings.json`（或 `C:\Users\Q\.claude\config\settings.json`）：
```json
{
  "mcpServers": {
    "src-hunter": {
      "command": "node",
      "args": ["C:/Users/Q/.claude/mcp-servers/src-hunter/dist/index.js"],
      "env": {
        "LOG_LEVEL": "info",
        "NODE_ENV": "production"
      }
    }
  }
}
```

### Step 5: 重启 Claude Code
```bash
# 重启 Claude Code 使配置生效
# 或运行
claude restart
```

### Step 6: 测试连接
在 Claude Code 中运行：
```typescript
// 检查工具是否可用
await mcp.call('src-hunter', 'get-rate-limits', {});

// 检查授权
await mcp.call('src-hunter', 'check-authorization', {
  target: 'example.com'
});
```

## 🔧 开发模式

### 实时编译
```bash
npm run watch
```

### 查看日志
```bash
# Windows
tail -f logs/combined.log

# 或使用 PowerShell
Get-Content logs/combined.log -Wait
```

### 调试模式
```bash
# 设置环境变量
set LOG_LEVEL=debug
npm run dev
```

## 📝 使用示例

### 示例 1: 同步 SRC 资产
```typescript
const result = await mcp.call('src-hunter', 'sync-src-assets', {
  platforms: ['360src', 'baidusrc'],
  force: true
});

console.log(`同步完成: ${result.synced} 个平台，共 ${result.total_assets} 个资产`);
```

### 示例 2: 完整侦察流程
```typescript
// 1. 检查授权
const auth = await mcp.call('src-hunter', 'check-authorization', {
  target: 'jd.com'
});

if (!auth.authorized) {
  console.log('目标未授权');
  return;
}

// 2. 子域名枚举
const subdomains = await mcp.call('src-hunter', 'enumerate-subdomains', {
  domain: 'jd.com',
  tools: ['subfinder', 'amass']
});

console.log(`发现 ${subdomains.count} 个子域名`);

// 3. 端口扫描（选一个子域名）
const ports = await mcp.call('src-hunter', 'port-scan', {
  target: 'api.jd.com',
  scan_type: 'common'
});

console.log(`开放端口: ${ports.open_ports.length}`);

// 4. Web 指纹识别
const fingerprint = await mcp.call('src-hunter', 'web-fingerprint', {
  url: 'https://api.jd.com'
});

console.log(`技术栈: ${fingerprint.technologies.map(t => t.name).join(', ')}`);

// 5. 漏洞扫描
const vulns = await mcp.call('src-hunter', 'vuln-scan', {
  target: 'https://api.jd.com',
  severity: ['critical', 'high'],
  safe_mode: true
});

console.log(`发现漏洞: ${vulns.stats.total}`);

// 6. 生成报告
const report = await mcp.call('src-hunter', 'generate-report', {
  scan_id: vulns.scan_id,
  format: 'md'
});

console.log(`报告路径: ${report.path}`);
```

## ⚠️ 常见问题

### 1. 工具未找到
```bash
# 确保 Go bin 目录在 PATH 中
# Windows: 添加到环境变量
C:\Users\Q\go\bin

# 或创建软链接
mklink "C:\Windows\System32\subfinder.exe" "C:\Users\Q\go\bin\subfinder.exe"
```

### 2. 权限错误
```bash
# WSL2 中可能需要 sudo
sudo nmap -Pn target.com

# 或给工具添加 capabilities（Linux）
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

### 3. Nuclei 模板缺失
```bash
# 手动更新模板
nuclei -update-templates

# 或指定模板目录
nuclei -u target.com -t ~/nuclei-templates/
```

### 4. 频率限制触发
```bash
# 查看当前限流状态
await mcp.call('src-hunter', 'get-rate-limits', {});

# 等待冷却时间后重试
```

### 5. 日志文件过大
```bash
# 清理旧日志
rm logs/*.log

# 或配置日志轮转（见 src/utils/logger.ts）
```

## 🔐 安全建议

1. **仅在授权环境使用**
   - 确保所有目标都在 `whitelist.json` 中
   - 定期审查审计日志 `data/audit.log`

2. **启用安全模式**
   - 所有扫描默认启用 `safe_mode: true`
   - 使用无害 payload 进行探测

3. **控制扫描强度**
   - 遵守频率限制
   - 避免触发目标 WAF

4. **保护敏感信息**
   - 不要在日志中记录敏感数据
   - 扫描报告应妥善保管

## 📊 性能优化

### 减少扫描时间
```typescript
// 使用 quick 模式
await mcp.call('src-hunter', 'port-scan', {
  target: 'example.com',
  scan_type: 'quick'  // 仅扫描 top 100 端口
});

// 限制子域名枚举工具
await mcp.call('src-hunter', 'enumerate-subdomains', {
  domain: 'example.com',
  tools: ['subfinder']  // 仅使用 subfinder（更快）
});
```

### 并行扫描（高级）
```typescript
// 同时扫描多个子域名（需创建 Agent）
const subdomains = ['api', 'admin', 'www'].map(sub => `${sub}.example.com`);

const results = await Promise.all(
  subdomains.map(target =>
    mcp.call('src-hunter', 'web-fingerprint', { url: `https://${target}` })
  )
);
```

## 🆘 获取帮助

- **Issues**: [GitHub Issues](https://github.com/your-repo/src-hunter/issues)
- **文档**: 参见 [README.md](README.md)
- **日志**: 查看 `logs/combined.log` 获取详细错误信息

## 🔄 更新

```bash
# 拉取最新代码
cd C:\Users\Q\.claude\mcp-servers\src-hunter
git pull

# 重新安装依赖
npm install

# 重新编译
npm run build

# 重启 Claude Code
```

---

**安装完成！** 🎉

运行 `npm run dev` 启动开发模式，或在 Claude Code 中直接调用工具。
