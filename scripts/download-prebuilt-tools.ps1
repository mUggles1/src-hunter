# ProjectDiscovery 工具预编译版本自动下载脚本
# 适用于 Windows PowerShell

Write-Host "========================================"
Write-Host "  SRC Hunter 工具自动下载脚本"
Write-Host "  (无需 Go 环境)"
Write-Host "========================================"
Write-Host ""

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "警告: 建议以管理员身份运行（用于修改系统 PATH）" -ForegroundColor Yellow
    Write-Host "   继续安装到用户目录..." -ForegroundColor Yellow
    Write-Host ""
}

# 创建工具目录
$toolsDir = "C:\Tools\SRCHunter"
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Write-Host "✓ 创建工具目录: $toolsDir"
} else {
    Write-Host "✓ 工具目录已存在: $toolsDir"
}
Write-Host ""

# ==================== 下载 Subfinder ====================
Write-Host "1/4: 下载 Subfinder..."
$subfinderDir = "$toolsDir\subfinder"
$subfinderVersion = "v2.6.6"
$subfinderUrl = "https://github.com/projectdiscovery/subfinder/releases/download/$subfinderVersion/subfinder_${subfinderVersion}_windows_amd64.zip"
$subfinderZip = "$env:TEMP\subfinder.zip"

try {
    if (-not (Test-Path "$subfinderDir\subfinder.exe")) {
        Write-Host "   下载中: $subfinderUrl"
        Invoke-WebRequest -Uri $subfinderUrl -OutFile $subfinderZip -UseBasicParsing
        Expand-Archive -Path $subfinderZip -DestinationPath $subfinderDir -Force
        Remove-Item $subfinderZip -Force
        Write-Host "✓ Subfinder 安装成功" -ForegroundColor Green
    } else {
        Write-Host "✓ Subfinder 已存在" -ForegroundColor Green
    }
}
catch {
    Write-Host "✗ Subfinder 下载失败: $_" -ForegroundColor Red
}
Write-Host ""

# ==================== 下载 httpx ====================
Write-Host "2/4: 下载 httpx..."
$httpxDir = "$toolsDir\httpx"
$httpxVersion = "v1.6.8"
$httpxUrl = "https://github.com/projectdiscovery/httpx/releases/download/$httpxVersion/httpx_${httpxVersion}_windows_amd64.zip"
$httpxZip = "$env:TEMP\httpx.zip"

try {
    if (-not (Test-Path "$httpxDir\httpx.exe")) {
        Write-Host "   下载中: $httpxUrl"
        Invoke-WebRequest -Uri $httpxUrl -OutFile $httpxZip -UseBasicParsing
        Expand-Archive -Path $httpxZip -DestinationPath $httpxDir -Force
        Remove-Item $httpxZip -Force
        Write-Host "✓ httpx 安装成功" -ForegroundColor Green
    } else {
        Write-Host "✓ httpx 已存在" -ForegroundColor Green
    }
}
catch {
    Write-Host "✗ httpx 下载失败: $_" -ForegroundColor Red
}
Write-Host ""

# ==================== 下载 Nuclei ====================
Write-Host "3/4: 下载 Nuclei..."
$nucleiDir = "$toolsDir\nuclei"
$nucleiVersion = "v3.3.8"
$nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/$nucleiVersion/nuclei_${nucleiVersion}_windows_amd64.zip"
$nucleiZip = "$env:TEMP\nuclei.zip"

try {
    if (-not (Test-Path "$nucleiDir\nuclei.exe")) {
        Write-Host "   下载中: $nucleiUrl"
        Invoke-WebRequest -Uri $nucleiUrl -OutFile $nucleiZip -UseBasicParsing
        Expand-Archive -Path $nucleiZip -DestinationPath $nucleiDir -Force
        Remove-Item $nucleiZip -Force
        Write-Host "✓ Nuclei 安装成功" -ForegroundColor Green

        Write-Host "   更新 Nuclei 模板..."
        & "$nucleiDir\nuclei.exe" -update-templates -silent
        Write-Host "✓ 模板更新完成" -ForegroundColor Green
    } else {
        Write-Host "✓ Nuclei 已存在" -ForegroundColor Green
    }
}
catch {
    Write-Host "✗ Nuclei 下载失败: $_" -ForegroundColor Red
}
Write-Host ""

# ==================== 配置 PATH ====================
Write-Host "4/4: 配置环境变量..."

$pathsToAdd = @(
    "$toolsDir\subfinder",
    "$toolsDir\httpx",
    "$toolsDir\nuclei"
)

$currentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)

foreach ($path in $pathsToAdd) {
    if ($currentPath -notlike "*$path*") {
        $currentPath += ";$path"
    }
}

try {
    [Environment]::SetEnvironmentVariable("Path", $currentPath, [System.EnvironmentVariableTarget]::User)
    Write-Host "✓ PATH 更新成功" -ForegroundColor Green
    Write-Host "   请重启终端以生效" -ForegroundColor Yellow
}
catch {
    Write-Host "✗ PATH 更新失败（需要手动添加）" -ForegroundColor Red
    Write-Host "   请添加以下路径到系统 PATH:" -ForegroundColor Yellow
    foreach ($path in $pathsToAdd) {
        Write-Host "   - $path" -ForegroundColor Yellow
    }
}

Write-Host ""

# ==================== 验证安装 ====================
Write-Host "========================================"
Write-Host "  安装验证"
Write-Host "========================================"
Write-Host ""

# 临时添加到当前会话的 PATH
$env:Path += ";$toolsDir\subfinder;$toolsDir\httpx;$toolsDir\nuclei"

$tools = @{
    "Subfinder" = "$toolsDir\subfinder\subfinder.exe"
    "httpx" = "$toolsDir\httpx\httpx.exe"
    "Nuclei" = "$toolsDir\nuclei\nuclei.exe"
}

$installed = 0
$total = $tools.Count

foreach ($tool in $tools.GetEnumerator()) {
    if (Test-Path $tool.Value) {
        Write-Host "✓ $($tool.Key)" -ForegroundColor Green
        $installed++
    } else {
        Write-Host "✗ $($tool.Key) - 未安装" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "已安装: $installed/$total"

if ($installed -eq $total) {
    Write-Host ""
    Write-Host "所有工具安装完成!" -ForegroundColor Green
    Write-Host ""
    Write-Host "下一步:"
    Write-Host "1. 重启终端（让 PATH 生效）"
    Write-Host "2. 验证: subfinder -version"
    Write-Host "3. 配置 SRC Hunter MCP Server"
    Write-Host "4. 重启 Claude Code"
} else {
    Write-Host ""
    Write-Host "部分工具下载失败" -ForegroundColor Yellow
    Write-Host "   可能原因: 网络问题、GitHub 访问受限"
    Write-Host ""
    Write-Host "解决方案:"
    Write-Host "1. 使用代理/VPN 后重新运行"
    Write-Host "2. 手动下载并解压到 $toolsDir"
    Write-Host "3. 查看详细错误信息"
}

Write-Host ""
Write-Host "工具安装路径: $toolsDir"
Write-Host "========================================"
