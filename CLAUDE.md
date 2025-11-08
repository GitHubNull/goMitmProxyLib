# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个 Go 语言编写的中间人代理库（goMitmProxyLib）。项目目前处于初始化阶段，使用模块化的设计思路。

## 项目结构

- `src/` - 源代码目录，所有 Go 源文件应放置在此处
- `doc/` - 文档目录，用于存放项目文档
- `README.md` - 项目说明文档
- `go.mod` - Go 模块文件（需要初始化）

## 开发指南

### 初始化 Go 模块
```bash
go mod init github.com/username/goMitmProxyLib
```

### 常用命令
- `go build ./src` - 构建项目
- `go test ./src...` - 运行所有测试
- `go test ./src -v` - 运行测试并显示详细输出
- `go run ./src/main.go` - 运行主程序
- `go mod tidy` - 整理模块依赖
- `go fmt ./src...` - 格式化代码
- `go vet ./src...` - 静态分析检查

### 代码组织原则
1. 使用模块化设计，降低单个文件长度
2. 每个功能模块应有独立的包和文件
3. 避免重复的源码文件或文档
4. 功能修复后必须测试验证

### 服务管理
- 任何后台运行的服务（特别是占用端口的服务）在使用完毕后必须主动关闭
- 使用 `Ctrl+C` 或适当的命令停止服务

## 架构说明

此项目预期实现中间人代理功能，可能包括：
- HTTP/HTTPS 代理服务器
- 证书生成和管理
- 请求/响应拦截和处理
- 流量分析和修改

具体的架构设计将在开发过程中逐步完善。