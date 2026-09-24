# SRC Hunter 安全工具安装脚本
# 用于 Windows 环境（Git Bash / WSL2）

echo "========================================"
echo "  SRC Hunter 安全工具自动安装脚本"
echo "========================================"
echo ""

# 检测操作系统
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "❌ 不支持的操作系统: $OSTYPE"
    exit 1
fi

echo "检测到操作系统: $OS"
echo ""

# ==================== 1. 检查 Go 环境 ====================
echo "📦 步骤 1/6: 检查 Go 环境..."

if command -v go &> /dev/null; then
    GO_VERSION=$(go version)
    echo "✅ Go 已安装: $GO_VERSION"
else
    echo "❌ Go 未安装"
    echo ""
    echo "请手动安装 Go:"
    echo "  Windows: https://go.dev/dl/go1.23.4.windows-amd64.msi"
    echo "  Linux: https://go.dev/dl/go1.23.4.linux-amd64.tar.gz"
    echo ""
    echo "安装后，确保 GOPATH/bin 在 PATH 中:"
    echo "  Windows: C:\\Users\\Q\\go\\bin"
    echo "  Linux: ~/go/bin"
    exit 1
fi

echo ""

# ==================== 2. 安装 Subfinder ====================
echo "📦 步骤 2/6: 安装 Subfinder（子域名枚举）..."

if command -v subfinder &> /dev/null; then
    echo "✅ Subfinder 已安装: $(subfinder -version 2>&1 | head -n1)"
else
    echo "⏳ 正在安装 Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

    if [ $? -eq 0 ]; then
        echo "✅ Subfinder 安装成功"
    else
        echo "❌ Subfinder 安装失败"
    fi
fi

echo ""

# ==================== 3. 安装 Httpx ====================
echo "📦 步骤 3/6: 安装 httpx（Web 探测）..."

if command -v httpx &> /dev/null; then
    echo "✅ httpx 已安装: $(httpx -version 2>&1 | head -n1)"
else
    echo "⏳ 正在安装 httpx..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

    if [ $? -eq 0 ]; then
        echo "✅ httpx 安装成功"
    else
        echo "❌ httpx 安装失败"
    fi
fi

echo ""

# ==================== 4. 安装 Nuclei ====================
echo "📦 步骤 4/6: 安装 Nuclei（漏洞扫描）..."

if command -v nuclei &> /dev/null; then
    echo "✅ Nuclei 已安装: $(nuclei -version 2>&1 | head -n1)"
else
    echo "⏳ 正在安装 Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

    if [ $? -eq 0 ]; then
        echo "✅ Nuclei 安装成功"
        echo "⏳ 更新 Nuclei 模板..."
        nuclei -update-templates -silent
        echo "✅ 模板更新完成"
    else
        echo "❌ Nuclei 安装失败"
    fi
fi

echo ""

# ==================== 5. 检查 Nmap ====================
echo "📦 步骤 5/6: 检查 Nmap（端口扫描）..."

if command -v nmap &> /dev/null; then
    echo "✅ Nmap 已安装: $(nmap --version | head -n1)"
else
    echo "⚠️  Nmap 未安装"
    echo ""
    echo "请手动安装 Nmap:"
    echo "  Windows: https://nmap.org/dist/nmap-7.95-setup.exe"
    echo "  Linux: sudo apt install nmap"
    echo ""
fi

echo ""

# ==================== 6. 安装 Dirsearch ====================
echo "📦 步骤 6/6: 安装 Dirsearch（目录扫描）..."

if command -v dirsearch &> /dev/null; then
    echo "✅ Dirsearch 已安装"
else
    echo "⏳ 正在安装 Dirsearch..."

    if command -v pip &> /dev/null || command -v pip3 &> /dev/null; then
        if command -v pip3 &> /dev/null; then
            pip3 install dirsearch
        else
            pip install dirsearch
        fi

        if [ $? -eq 0 ]; then
            echo "✅ Dirsearch 安装成功"
        else
            echo "❌ Dirsearch 安装失败"
        fi
    else
        echo "⚠️  Python pip 未安装，跳过 Dirsearch"
        echo "   请先安装 Python: https://www.python.org/downloads/"
    fi
fi

echo ""
echo "========================================"
echo "  安装总结"
echo "========================================"
echo ""

# 最终检查
TOOLS=("subfinder" "httpx" "nuclei" "nmap" "dirsearch")
INSTALLED=0
TOTAL=${#TOOLS[@]}

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✅ $tool"
        ((INSTALLED++))
    else
        echo "❌ $tool - 未安装"
    fi
done

echo ""
echo "已安装: $INSTALLED/$TOTAL"

if [ $INSTALLED -eq $TOTAL ]; then
    echo ""
    echo "🎉 所有工具安装完成！"
    echo ""
    echo "下一步："
    echo "1. 配置白名单: data/whitelist.json"
    echo "2. 注册到 Claude Code"
    echo "3. 重启 Claude Code"
    echo "4. 测试连接: /check-authorization target=example.com"
else
    echo ""
    echo "⚠️  部分工具未安装，请参考上方提示手动安装"
fi

echo ""
echo "详细文档: INSTALL.md"
echo "========================================"
