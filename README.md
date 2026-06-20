# Terraform Lint - Terraform HCL 静态分析与安全合规检测工具

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Terraform Lint 是一个强大的 Terraform HCL 静态分析与安全合规检测命令行工具，帮助 DevOps 工程师在本地或 CI 流水线中扫描 Terraform 配置文件，检测安全风险、最佳实践违规和成本优化建议。

## ✨ 功能特性

### 🔍 HCL 解析引擎
- 递归扫描指定目录下所有 `.tf` 和 `.tfvars` 文件
- 解析 HCL2 语法构建 AST（抽象语法树）
- 支持变量引用解析 (`var.xxx`)、本地值 (`locals`) 展开
- 模块引用 (`module`) 追踪，递归进入子模块目录分析
- 动态表达式标记为"动态值无法静态确定"但不跳过资源检查
- 解析失败时输出具体行号和原因，不中断整体扫描

### 🛡️ 安全规则集 (30+ 条)
| 规则 ID | 描述 | 严重级别 |
|---------|------|----------|
| S3_BUCKET_ENCRYPTION | S3 存储桶未启用加密 | warning |
| S3_BUCKET_PUBLIC_ACL | S3 ACL 使用 public-read 或 public-read-write | error |
| SECURITY_GROUP_OPEN | 安全组入站规则包含 0.0.0.0/0 | error |
| DB_PUBLICLY_ACCESSIBLE | 数据库公开访问 | error |
| IAM_WILDCARD_ACTION | IAM Policy Action 包含 `*` | warning |
| INSTANCE_NO_VPC | EC2 实例未指定 VPC | warning |
| SENSITIVE_DATA | 变量默认值包含疑似密钥 | error |
| OUTPUT_SENSITIVE | Output 未设置 sensitive 但值含密钥 | error |
| LOCAL_BACKEND | Backend 使用本地文件存储状态 | warning |
| ... | ... | ... |

### 📋 最佳实践规则集 (20+ 条)
| 规则 ID | 描述 | 严重级别 |
|---------|------|----------|
| NAMING_CONVENTION | 资源名/变量名不符合 snake_case 格式 | info |
| RESOURCE_TAGS | 资源缺少必需标签 (Environment, Owner) | info |
| VARIABLE_DESCRIPTION | Variable 缺少 description 字段 | info |
| OUTPUT_DESCRIPTION | Output 缺少 description 字段 | info |
| PROVIDER_VERSION | Provider 未指定版本约束 | warning |
| RESOURCE_PREFIX | 资源名包含重复的资源类型前缀 | info |
| TERRAFORM_VERSION | 未指定 Terraform 版本约束 | warning |
| ... | ... | ... |

### 💰 成本优化规则集 (10+ 条)
| 规则 ID | 描述 | 严重级别 |
|---------|------|----------|
| EXPENSIVE_INSTANCE_TYPE | 使用昂贵的实例类型 (x1/p3/p4 等) | info |
| RDS_MULTI_AZ_SMALL | 小实例启用多可用区 | info |
| UNUSED_EIP | 未关联的弹性 IP | info |
| NAT_GATEWAY_COUNT | NAT 网关数量过多 | info |
| LARGE_VOLUME_SIZE | EBS 卷过大 | info |
| EXCESSIVE_PROVISIONED_IOPS | 预配置 IOPS 过高 | info |
| S3_INTELLIGENT_TIERING | 未配置 S3 智能分层 | info |
| ... | ... | ... |

### ⚙️ 规则配置
- 支持 `.tflint.yaml` 或 `.tflint.json` 配置文件
- 启用/禁用特定规则 ID
- 调整规则严重级别 (error/warning/info)
- 配置规则参数 (标签名列表、命名正则、排除目录)
- 全局忽略路径设置
- 行内注释忽略：`# tflint:ignore:RULE_ID`

### 📤 输出格式
- **terminal** (默认)：彩色终端表格
- **json**：完整结构化结果
- **sarif**：GitHub Code Scanning 兼容的 SARIF v2.1.0 格式
- **junit**：JUnit XML 格式，可被 CI 系统解析
- **markdown**：Markdown 表格，可直接贴到 PR 评论

### 🚪 退出码策略
- 无任何发现：退出 `0`
- 只有 info 和 warning：退出 `0`
- 存在 error 级别：退出 `1` (用于 CI 阻断)
- 可通过 `--fail-on` 参数调整

### ⚡ 性能
- 并发扫描 (多个文件同时解析和检查)
- 大型项目 (500+ .tf 文件) 10 秒内完成
- 增量模式：`--changed-only`，配合 git diff 只扫描有变更的文件

## 📦 安装

### 从源码构建

#### 前置要求
- Go 1.21 或更高版本

#### 构建步骤

```bash
# 克隆仓库
git clone <repository-url>
cd terraform-lint

# 下载依赖
export GO111MODULE=on
export GOPROXY=https://goproxy.cn,direct  # 国内用户建议使用
go mod download
go mod tidy

# 构建
go build -o terraform-lint ./cmd/terraform-lint

# 验证
./terraform-lint version
```

详细构建说明请查看 [BUILD.md](BUILD.md)。

## 🚀 快速开始

### 1. 查看版本
```bash
terraform-lint version
```

### 2. 查看所有可用规则
```bash
# 列出所有规则
terraform-lint rules

# 按类别过滤
terraform-lint rules --category security

# 使用配置文件
terraform-lint rules --config .tflint.yaml
```

### 3. 生成默认配置文件
```bash
terraform-lint init

# 指定输出路径并覆盖
terraform-lint init --output .tflint.yaml --force
```

### 4. 扫描 Terraform 配置
```bash
# 扫描当前目录
terraform-lint scan

# 指定目录
terraform-lint scan --dir ./terraform

# JSON 格式输出
terraform-lint scan --format json

# 输出到文件
terraform-lint scan --format sarif --output results.sarif

# 增量扫描（只扫描 git 变更文件）
terraform-lint scan --changed-only

# 自动修复
terraform-lint scan --fix

# CI 中使用，warning 也阻断
terraform-lint scan --fail-on warning
```

### 5. 配置文件示例

```yaml
# .tflint.yaml
ignore_paths:
  - ".git/"
  - "node_modules/"
  - "vendor/"
  - ".terraform/"

global:
  required_tags:
    - Environment
    - Owner
    - Project
  naming_regex: "^[a-z_][a-z0-9_]*$"
  max_concurrency: 8

rules:
  S3_BUCKET_ENCRYPTION:
    enabled: true
    severity: warning

  RESOURCE_TAGS:
    enabled: true
    severity: info
    params:
      required_tags:
        - Environment
        - Owner

  EXPENSIVE_INSTANCE_TYPE:
    enabled: true
    severity: info
    params:
      expensive_families:
        - p2
        - p3
        - p4
```

## 📁 项目结构

```
terraform-lint/
├── cmd/
│   └── terraform-lint/
│       └── main.go              # CLI 入口
├── internal/
│   ├── ast/
│   │   └── ast.go               # HCL 解析和 AST 处理
│   ├── cli/
│   │   ├── root.go              # 根命令
│   │   ├── scan.go              # scan 子命令
│   │   ├── init.go              # init 子命令
│   │   ├── rules.go             # rules 子命令
│   │   └── version.go           # version 子命令
│   ├── config/
│   │   └── config.go            # 配置加载
│   ├── fixer/
│   │   └── fixer.go             # 自动修复
│   ├── git/
│   │   └── git.go               # Git 集成
│   ├── output/
│   │   ├── output.go            # 输出接口
│   │   ├── terminal.go          # 终端输出
│   │   ├── json.go              # JSON 输出
│   │   ├── sarif.go             # SARIF 输出
│   │   ├── junit.go             # JUnit 输出
│   │   └── markdown.go          # Markdown 输出
│   ├── parser/
│   │   └── parser.go            # 文件解析器
│   ├── rules/
│   │   ├── base.go              # 基础规则类
│   │   ├── registry.go          # 规则注册表
│   │   ├── security/            # 安全规则 (30条)
│   │   ├── bestpractice/        # 最佳实践规则 (20条)
│   │   └── cost/                # 成本优化规则 (10条)
│   ├── scanner/
│   │   └── scanner.go           # 扫描引擎
│   ├── types/
│   │   └── types.go             # 核心类型定义
│   └── utils/
│       └── utils.go             # 工具函数
├── examples/
│   ├── main.tf                  # 示例 Terraform 文件
│   └── .tflint.example.yaml     # 示例配置文件
├── go.mod
├── Makefile
├── BUILD.md                     # 构建说明
└── README.md
```

## 🔧 CI/CD 集成

### GitHub Actions

```yaml
name: Terraform Lint
on: [pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'
          
      - name: Build terraform-lint
        run: |
          go build -o terraform-lint ./cmd/terraform-lint
          
      - name: Run terraform-lint
        run: |
          ./terraform-lint scan --format sarif --output tflint-results.sarif
          
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tflint-results.sarif
```

### GitLab CI

```yaml
stages:
  - lint

terraform_lint:
  stage: lint
  image: golang:1.21
  script:
    - go build -o terraform-lint ./cmd/terraform-lint
    - ./terraform-lint scan --format junit --output tflint-results.xml
  artifacts:
    reports:
      junit: tflint-results.xml
    when: always
```

## 🤝 贡献

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📝 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🆘 支持

如果遇到问题或有建议，请 [创建 Issue](../../issues)。

---

**Terraform Lint** - 让您的 Terraform 配置更安全、更规范、更经济！
