# GoMitmProxyLib - 使用指南和通知

## 📋 项目概述

GoMitmProxyLib 是一个用Go语言编写的高性能HTTP(S)中间人代理库，专为网络流量分析、安全测试和开发调试而设计。

### 主要功能
- HTTP/HTTPS 代理转发 (性能：31091+ RPS)
- 细粒度钩子系统 (14种拦截点)
- 事件驱动架构
- 动态证书生成和管理
- 结构化日志系统
- 高并发连接处理

## 🎯 适用场景

### ✅ 推荐用途
- **网络应用开发调试**：分析和调试HTTP/HTTPS通信
- **安全研究**：在授权环境中进行安全测试和漏洞分析
- **API测试**：模拟和测试各种网络请求场景
- **性能分析**：监控和分析网络应用性能
- **教学演示**：用于网络协议和代理技术的教学

### ❌ 禁止用途
- 未授权的网络入侵或攻击
- 窃取或拦截他人的敏感数据
- 违反隐私法规的数据收集
- 任何非法或恶意的网络活动

## 🔧 使用指南

### 快速开始
```go
package main

import (
    "github.com/mintux/goMitmProxyLib/src"
    "github.com/mintux/goMitmProxyLib/src/types"
)

func main() {
    // 创建配置
    config := &types.Config{
        ListenAddr:  ":8080",
        EnableHTTPS: true,
        LogLevel:    "info",
    }

    // 创建代理实例
    proxy, err := src.NewMitmProxy(config)
    if err != nil {
        panic(err)
    }

    // 启动代理服务器
    if err := proxy.Start(); err != nil {
        panic(err)
    }

    // 程序结束时停止代理
    defer proxy.Stop()
}
```

### 配置选项
```go
config := &types.Config{
    ListenAddr:           ":8080",        // 监听地址
    EnableHTTPS:          true,          // 启用HTTPS支持
    MaxIdleConns:         100,           // 最大空闲连接数
    MaxIdleConnsPerHost:  10,            // 每个主机最大空闲连接数
    IdleConnTimeout:      90 * time.Second, // 空闲连接超时
    ReadTimeout:          5 * time.Second,  // 读取超时
    WriteTimeout:         5 * time.Second,  // 写入超时
    LogLevel:             "info",         // 日志级别
    LogFormat:            "json",        // 日志格式
    CACertFile:          "./ca.crt",    // CA证书文件路径
    CAKeyFile:           "./ca.key",    // CA私钥文件路径
}
```

### 钩子使用示例
```go
// 注册请求拦截钩子
proxy.GetHookManager().Register(hooks.HookOnRequestReceived,
    func(ctx *types.ProxyContext) *types.HookResult {
        // 记录请求信息
        fmt.Printf("收到请求: %s %s\n", ctx.Request.Method, ctx.Request.URL)
        return &types.HookResult{Action: types.ActionContinue}
    },
    &hooks.HookMetadata{
        Name: "request_logger",
        Description: "记录所有请求信息",
    })
```

## 🔐 安全注意事项

### 证书管理
1. **证书隔离**：测试证书应与生产环境证书完全隔离
2. **权限控制**：确保证书文件仅授权用户可访问
3. **定期轮换**：定期更新和轮换测试证书
4. **安全存储**：私钥文件应妥善保管，避免泄露

### 网络安全
1. **防火墙配置**：限制代理服务器的网络访问范围
2. **访问控制**：实施严格的访问认证和授权机制
3. **流量监控**：监控代理流量，及时发现异常行为
4. **日志审计**：保留详细的访问日志用于审计

### 数据保护
1. **敏感数据**：避免在日志中记录敏感信息
2. **数据清理**：定期清理测试过程中收集的数据
3. **加密存储**：对需要保存的敏感数据进行加密
4. **隐私合规**：确保数据处理符合隐私法规要求

## 📊 性能特性

### 基准测试结果
- **吞吐量**：31091.87 requests/sec
- **成功率**：100.00%
- **平均响应时间**：304.328µs
- **并发连接**：支持数千并发连接

### 性能优化建议
1. **连接池**：合理配置连接池大小
2. **缓冲区**：适当调整读写缓冲区大小
3. **超时设置**：根据应用场景调整超时参数
4. **日志级别**：生产环境使用info或error级别

## 🔍 故障排除

### 常见问题
1. **证书错误**：检查CA证书是否正确安装和信任
2. **连接超时**：调整超时配置或检查网络连接
3. **性能问题**：监控资源使用情况，优化配置参数
4. **权限错误**：确保程序有足够的权限访问所需资源

### 调试技巧
1. **详细日志**：启用debug级别日志获取详细信息
2. **性能分析**：使用内置性能测试工具分析瓶颈
3. **网络抓包**：使用wireshark等工具分析网络流量
4. **单元测试**：运行完整的测试套件验证功能

## 📚 相关资源

### 文档
- [API文档](./docs/api.md)
- [使用示例](./examples/)
- [性能测试指南](./docs/performance.md)

### 依赖项
- Go 1.21+
- 标准库依赖

### 第三方工具
- [Go官方文档](https://golang.org/doc/)
- [HTTP代理协议规范](https://tools.ietf.org/html/rfc7230)
- [TLS协议规范](https://tools.ietf.org/html/rfc5246)

## 🚨 重要警告

### 法律合规
- **授权要求**：仅在获得明确授权的环境中使用
- **法律法规**：严格遵守当地相关法律法规
- **隐私保护**：尊重用户隐私，保护敏感数据

### 技术风险
- **系统影响**：可能影响目标系统的正常运行
- **网络稳定**：可能影响网络连接的稳定性
- **安全风险**：不当使用可能带来安全风险

---

**本通知文档可能不时更新，请定期查看最新版本。**

**最后更新：2025年11月8日**