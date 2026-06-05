# ArgusMind 一键启动脚本 (Windows PowerShell)
# 先启动后端（port 6066），再启动前端（port 8000）
# 如果已有服务在运行，先停止再重启

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$BackendPort = 6066
$FrontendPort = 8000

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ArgusMind 启动脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# -------------------------------------------
# 辅助函数：按端口终止进程
# -------------------------------------------
function Stop-ProcessOnPort($Port, $Name) {
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "[$Name] 发现已有进程 $($proc.ProcessName) (PID: $($proc.Id)) 占用端口 $Port，正在终止..." -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Write-Host "[$Name] 已终止旧进程" -ForegroundColor Green
        }
    }
    else {
        Write-Host "[$Name] 端口 $Port 无占用，无需停止" -ForegroundColor Gray
    }
}

# -------------------------------------------
# 1. 停止已有服务
# -------------------------------------------
Write-Host "`n[1/4] 检查并停止已有服务..." -ForegroundColor Cyan
Stop-ProcessOnPort -Port $BackendPort -Name "后端"
Stop-ProcessOnPort -Port $FrontendPort -Name "前端"

# -------------------------------------------
# 2. 检查 Python 虚拟环境
# -------------------------------------------
Write-Host "`n[2/4] 检查 Python 环境..." -ForegroundColor Cyan
$VenvPath = Join-Path $ProjectRoot ".venv"
if (Test-Path "$VenvPath\Scripts\python.exe") {
    Write-Host "使用虚拟环境: $VenvPath" -ForegroundColor Green
    $Python = "$VenvPath\Scripts\python.exe"
    $Uvicorn = "$VenvPath\Scripts\uvicorn.exe"
}
else {
    Write-Host "未找到 .venv，使用系统 Python" -ForegroundColor Yellow
    $Python = "python"
    $Uvicorn = "uvicorn"
}

# 检查 uvicorn 是否可用
$uvicornCheck = & $Python -c "import uvicorn" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "错误: uvicorn 未安装，请先执行 pip install uvicorn[standard]" -ForegroundColor Red
    exit 1
}

# -------------------------------------------
# 3. 启动后端
# -------------------------------------------
Write-Host "`n[3/4] 启动后端 (FastAPI, port $BackendPort)..." -ForegroundColor Cyan

$BackendArgs = @(
    "-m", "uvicorn",
    "src.api.app:create_app",
    "--factory",
    "--host", "0.0.0.0",
    "--port", "$BackendPort",
    "--reload"
)

$BackendProcess = Start-Process -FilePath $Python -ArgumentList $BackendArgs -PassThru -WindowStyle Minimized -WorkingDirectory $ProjectRoot

Write-Host "后端进程已启动 (PID: $($BackendProcess.Id))，等待就绪..." -ForegroundColor Gray

# 等待后端就绪
$MaxWait = 30
for ($i = 1; $i -le $MaxWait; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:${BackendPort}/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "后端就绪 (http://127.0.0.1:${BackendPort})" -ForegroundColor Green
            break
        }
    }
    catch {}
    Start-Sleep -Seconds 1
}
if ($i -gt $MaxWait) {
    Write-Host "警告: 后端在 ${MaxWait}s 内未就绪，继续启动前端..." -ForegroundColor Yellow
}

# -------------------------------------------
# 4. 启动前端
# -------------------------------------------
Write-Host "`n[4/4] 启动前端 (Ant Design Pro, port $FrontendPort)..." -ForegroundColor Cyan

$FrontendDir = Join-Path $ProjectRoot "frontend"
if (-not (Test-Path "$FrontendDir\node_modules")) {
    Write-Host "node_modules 未找到，正在安装前端依赖..." -ForegroundColor Yellow
    Push-Location $FrontendDir
    npm install
    Pop-Location
}

Push-Location $FrontendDir
$FrontendProcess = Start-Process -FilePath "npm" -ArgumentList "run", "start" -PassThru -WindowStyle Minimized -WorkingDirectory $FrontendDir
Pop-Location

Write-Host "前端进程已启动 (PID: $($FrontendProcess.Id))" -ForegroundColor Gray

# 等待前端就绪
for ($i = 1; $i -le $MaxWait; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:${FrontendPort}" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "前端就绪 (http://127.0.0.1:${FrontendPort})" -ForegroundColor Green
            break
        }
    }
    catch {}
    Start-Sleep -Seconds 1
}
if ($i -gt $MaxWait) {
    Write-Host "前端正在编译中，请稍候查看 http://127.0.0.1:${FrontendPort}" -ForegroundColor Yellow
}

# -------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  ArgusMind 启动完成" -ForegroundColor Green
Write-Host "  后端: http://127.0.0.1:${BackendPort}" -ForegroundColor White
Write-Host "  API:  http://127.0.0.1:${BackendPort}/api" -ForegroundColor White
Write-Host "  前端: http://127.0.0.1:${FrontendPort}" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n按 Ctrl+C 或关闭终端窗口停止所有服务" -ForegroundColor Gray
