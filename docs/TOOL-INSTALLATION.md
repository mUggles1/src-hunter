# SRC Hunter 安全工具安装指南
# Windows 用户推荐方案

## 方案选择

### 🎯 方案 A：使用 WSL2（推荐）

WSL2 提供完整的 Linux 环境，工具兼容性最好。

#### 1. 启用 WSL2
```powershell
# 以管理员身份运行 PowerShell
wsl --install
# 重启电脑后，安装 Ubuntu
```

#### 2. 在 WSL2 中安装工具
```bash
# 进入 WSL2
wsl

# 安装 Go
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# 安装安全工具
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# 安装 Nmap
sudo apt update && sudo apt install -y nmap

# 安装 Dirsearch
pip3 install dirsearch

# 验证
subfinder -version
httpx -version
nuclei -version
nmap --version
dirsearch --version
```

---

### 🔧 方案 B：原生 Windows 安装

#### 1. 安装 Go
下载：https://go.dev/dl/go1.23.4.windows-amd64.msi

安装后，确认环境变量：
```powershell
# 检查 Go
go version

# 确保 GOPATH/bin 在 PATH 中
echo $env:Path | Select-String "go\\bin"
# 如果没有，手动添加：
# 系统属性 → 环境变量 → Path → 新建 → C:\Users\Q\go\bin
```

#### 2. 安装 Go 工具
```powershell
# 打开 PowerShell
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 更新 Nuclei 模板
nuclei -update-templates
```

#### 3. 安装 Nmap
下载：https://nmap.org/dist/nmap-7.95-setup.exe
运行安装程序，默认选项即可。

#### 4. 安装 Python 和 Dirsearch
```powershell
# 下载 Python: https://www.python.org/downloads/
# 安装时勾选 "Add Python to PATH"

# 安装 Dirsearch
pip install dirsearch
```

#### 5. 验证安装
```powershell
subfinder -version
httpx -version
nuclei -version
nmap --version
dirsearch --version
```

---

### ⚡ 方案 C：一键安装脚本（Git Bash）

如果你已安装 Git for Windows，可以使用自动化脚本：

```bash
# 在 Git Bash 中运行
cd /c/Users/Q/.claude/mcp-servers/src-hunter/scripts
./install-tools.sh
```

该脚本会：
- 检测 Go 环境
- 自动安装 Subfinder、httpx、Nuclei
- 检查 Nmap 和 Dirsearch
- 生成安装报告

---

## 常见问题

### Q1: 找不到 Go 命令
**解决**：
```powershell
# 检查 Go 是否安装
where go

# 如果未找到，手动添加到 PATH
$env:Path += ";C:\Program Files\Go\bin;C:\Users\Q\go\bin"

# 永久添加（需管理员权限）
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
```

### Q2: Nuclei 模板下载失败
**解决**：
```bash
# 使用国内镜像（如果在中国）
export GOPROXY=https://goproxy.cn,direct
nuclei -update-templates

# 或手动下载模板
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates
```

### Q3: Nmap 权限错误
**解决**：
- Windows: 以管理员身份运行 PowerShell
- WSL2: 使用 `sudo nmap ...`

### Q4: Go 工具安装后找不到
**解决**：
```bash
# 检查 GOPATH
go env GOPATH

# 工具应该在
# Windows: %GOPATH%\bin (通常是 C:\Users\Q\go\bin)
# Linux: $GOPATH/bin (通常是 ~/go/bin)

# 确保该目录在 PATH 中
```

### Q5: WSL2 访问 Windows 文件慢
**解决**：
```bash
# 将项目复制到 WSL2 内部
cp -r /mnt/c/Users/Q/.claude/mcp-servers/src-hunter ~/src-hunter

# 在 WSL2 中编译和运行
cd ~/src-hunter
npm install
npm run build
```

---

## 安装验证清单

安装完成后，运行以下命令验证：

```bash
# 检查所有工具
echo "=== 工具版本检查 ==="
echo "Subfinder: $(subfinder -version 2>&1 | head -n1)"
echo "httpx: $(httpx -version 2>&1 | head -n1)"
echo "Nuclei: $(nuclei -version 2>&1 | head -n1)"
echo "Nmap: $(nmap --version | head -n1)"
echo "Dirsearch: $(dirsearch --version 2>&1 || echo '已安装')"
echo "========================"

# 测试工具是否可用
subfinder -d example.com -silent -max-time 5
httpx -u https://example.com -silent
nuclei -u https://example.com -silent -timeout 5
nmap -Pn -p 80,443 example.com
```

如果所有命令都能正常执行，说明安装成功！

---

## 下一步

工具安装完成后：

1. **配置白名单**：编辑 `data/whitelist.json`
2. **注册 MCP Server**：编辑 `~/.claude/config/settings.json`
3. **重启 Claude Code**
4. **测试连接**：在 Claude Code 中运行测试命令

详见 [QUICKSTART.md](QUICKSTART.md)
