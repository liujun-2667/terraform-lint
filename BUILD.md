# 构建说明

## 前置要求

- Go 1.21 或更高版本
- Git (可选，用于增量扫描功能)

## 安装 Go

### Windows

1. 下载 Go 安装包: https://go.dev/dl/go1.21.6.windows-amd64.msi
2. 运行安装程序，按照提示完成安装
3. 重新打开命令行窗口，验证安装:
   ```powershell
   go version
   ```

### Linux

```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
```

### macOS

```bash
brew install go
go version
```

## 构建项目

### Windows (PowerShell)

```powershell
# 设置环境变量
$env:GO111MODULE = "on"
$env:GOPROXY = "https://goproxy.cn,direct"  # 国内用户建议使用

# 下载依赖
go mod download
go mod tidy

# 构建
go build -o terraform-lint.exe ./cmd/terraform-lint

# 验证
.\terraform-lint.exe version
```

### Linux/macOS

```bash
export GO111MODULE=on
export GOPROXY=https://goproxy.cn,direct  # 国内用户建议使用

# 下载依赖
go mod download
go mod tidy

# 构建
go build -o terraform-lint ./cmd/terraform-lint

# 验证
./terraform-lint version
```

## 使用 Makefile 构建

### 所有平台

```bash
# 构建当前平台
make build

# 构建所有平台
make build-all

# 运行测试
make test

# 安装到系统
make install
```

### Windows 使用 Makefile

需要先安装 Make (可以通过 Chocolatey 或 WSL)

```powershell
# 使用 Chocolatey 安装 make
choco install make

# 然后使用 make 命令
make build
```

## 交叉编译

### Linux

```bash
# 构建 Windows 版本
GOOS=windows GOARCH=amd64 go build -o terraform-lint.exe ./cmd/terraform-lint

# 构建 macOS 版本
GOOS=darwin GOARCH=amd64 go build -o terraform-lint-darwin ./cmd/terraform-lint
GOOS=darwin GOARCH=arm64 go build -o terraform-lint-darwin-arm64 ./cmd/terraform-lint
```

### Windows

```powershell
# 构建 Linux 版本
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o terraform-lint-linux ./cmd/terraform-lint

# 构建 macOS 版本
$env:GOOS="darwin"; $env:GOARCH="amd64"; go build -o terraform-lint-darwin ./cmd/terraform-lint
```

## 常见问题

### 1. 下载依赖超时

设置国内代理:
```bash
export GOPROXY=https://goproxy.cn,direct
```

### 2. 构建失败，提示缺少包

运行:
```bash
go mod tidy
```

### 3. 权限问题 (Linux/macOS)

```bash
chmod +x terraform-lint
```

## 验证安装

```bash
# 查看版本
./terraform-lint version

# 查看可用规则
./terraform-lint rules

# 扫描示例目录
./terraform-lint scan --dir examples

# 生成默认配置
./terraform-lint init
```

## 构建产物

构建完成后，会生成以下文件（取决于构建目标）:
- `terraform-lint` (Linux/macOS)
- `terraform-lint.exe` (Windows)

这是一个静态编译的二进制文件，不需要额外的运行时依赖，可以直接复制到任何支持的系统上运行。
