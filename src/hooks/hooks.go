package hooks

import (
	"github.com/mintux/goMitmProxyLib/src/types"
)

// HookFunc 定义钩子函数的通用类型
type HookFunc interface{}

// ConnectionHook 连接相关钩子
type ConnectionHook func(ctx *types.ProxyContext) *types.HookResult

// TLSHandshakeHook TLS握手钩子
type TLSHandshakeHook func(ctx *types.ProxyContext, handshakeInfo *types.TLSHandshakeInfo) *types.HookResult

// RequestHook 请求钩子
type RequestHook func(ctx *types.ProxyContext) *types.HookResult

// RequestHeaderHook 请求头钩子
type RequestHeaderHook func(ctx *types.ProxyContext) *types.HookResult

// RequestBodyHook 请求体钩子
type RequestBodyHook func(ctx *types.ProxyContext, body []byte) *types.HookResult

// ResponseHook 响应钩子
type ResponseHook func(ctx *types.ProxyContext) *types.HookResult

// ResponseHeaderHook 响应头钩子
type ResponseHeaderHook func(ctx *types.ProxyContext) *types.HookResult

// ResponseBodyHook 响应体钩子
type ResponseBodyHook func(ctx *types.ProxyContext, body []byte) *types.HookResult

// DataChunkHook 数据块传输钩子
type DataChunkHook func(ctx *types.ProxyContext, isUpload bool, chunk []byte) *types.HookResult

// ErrorHook 错误处理钩子
type ErrorHook func(ctx *types.ProxyContext, err error) *types.HookResult

// HookType 钩子类型枚举
type HookType string

const (
	// 连接相关钩子
	HookOnClientConnect      HookType = "on_client_connect"
	HookOnClientDisconnect   HookType = "on_client_disconnect"
	HookOnServerConnect      HookType = "on_server_connect"
	HookOnServerDisconnect   HookType = "on_server_disconnect"

	// TLS相关钩子
	HookOnTLSHandshakeStart  HookType = "on_tls_handshake_start"
	HookOnTLSHandshakeComplete HookType = "on_tls_handshake_complete"
	HookOnTLSCertificateGenerated HookType = "on_tls_certificate_generated"

	// 请求相关钩子
	HookOnRequestReceived    HookType = "on_request_received"
	HookOnRequestHeader      HookType = "on_request_header"
	HookOnRequestBody        HookType = "on_request_body"
	HookOnRequestSent        HookType = "on_request_sent"

	// 响应相关钩子
	HookOnResponseReceived   HookType = "on_response_received"
	HookOnResponseHeader     HookType = "on_response_header"
	HookOnResponseBody       HookType = "on_response_body"
	HookOnResponseSent       HookType = "on_response_sent"

	// 数据传输钩子
	HookOnDataChunk          HookType = "on_data_chunk"

	// 错误处理钩子
	HookOnError              HookType = "on_error"
)

// HookMetadata 钩子元数据
type HookMetadata struct {
	Name        string
	Description string
	Priority    int // 优先级，数字越大优先级越高
	Version     string
	Author      string
}

// HookRegistration 钩子注册信息
type HookRegistration struct {
	Hook      HookFunc
	Metadata  *HookMetadata
	Type      HookType
	Enabled   bool
}

// HookManager 钩子管理器接口
type HookManager interface {
	// 注册钩子
	Register(hookType HookType, hook HookFunc, metadata *HookMetadata) error

	// 注销钩子
	Unregister(hookType HookType, hookName string) error

	// 执行钩子
	ExecuteHook(hookType HookType, ctx *types.ProxyContext, args ...interface{}) *types.HookResult

	// 启用/禁用钩子
	EnableHook(hookType HookType, hookName string) error
	DisableHook(hookType HookType, hookName string) error

	// 获取已注册的钩子列表
	GetRegisteredHooks(hookType HookType) []*HookRegistration

	// 清空所有钩子
	Clear()

	// 获取钩子统计信息
	GetHookStats() map[HookType]int
}

// HookExecutor 钩子执行器接口
type HookExecutor interface {
	// 执行单个钩子
	Execute(registration *HookRegistration, ctx *types.ProxyContext, args ...interface{}) *types.HookResult

	// 执行钩子链（按优先级顺序）
	ExecuteChain(hookManager HookManager, hookType HookType, ctx *types.ProxyContext, args ...interface{}) *types.HookResult

	// 设置是否在第一个非Continue结果时停止
	SetStopOnFirstAction(stop bool)

	// 设置并行执行
	SetParallelExecution(parallel bool)
}

// HookFilter 钩子过滤器接口
type HookFilter interface {
	// 过滤钩子
	Filter(hookType HookType, hooks []*HookRegistration) []*HookRegistration

	// 添加过滤条件
	AddCondition(condition func(*HookRegistration) bool)

	// 移除过滤条件
	RemoveCondition(index int)
}

// HookValidator 钩子验证器接口
type HookValidator interface {
	// 验证钩子函数签名
	ValidateHook(hookType HookType, hook HookFunc) error

	// 验证钩子元数据
	ValidateMetadata(metadata *HookMetadata) error
}