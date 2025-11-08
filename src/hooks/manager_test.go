package hooks

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/mintux/goMitmProxyLib/src/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultHookManager(t *testing.T) {
	manager := NewDefaultHookManager()
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.GetHookStats())
}

func TestHookRegistration(t *testing.T) {
	manager := NewDefaultHookManager()

	// 创建测试钩子
	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook for testing",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 测试注册
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	assert.NoError(t, err)

	// 验证注册
	registeredHooks := manager.GetRegisteredHooks(HookOnRequestReceived)
	assert.Len(t, registeredHooks, 1)
	assert.Equal(t, "test_hook", registeredHooks[0].Metadata.Name)
	assert.True(t, registeredHooks[0].Enabled)
}

func TestDuplicateHookRegistration(t *testing.T) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 第一次注册
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	assert.NoError(t, err)

	// 第二次注册同名钩子应该失败
	err = manager.Register(HookOnRequestReceived, hookFunc, metadata)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestHookUnregistration(t *testing.T) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 注册钩子
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	require.NoError(t, err)

	// 验证注册
	registeredHooks := manager.GetRegisteredHooks(HookOnRequestReceived)
	assert.Len(t, registeredHooks, 1)

	// 注销钩子
	err = manager.Unregister(HookOnRequestReceived, "test_hook")
	assert.NoError(t, err)

	// 验证注销
	registeredHooks = manager.GetRegisteredHooks(HookOnRequestReceived)
	assert.Len(t, registeredHooks, 0)
}

func TestHookExecution(t *testing.T) {
	manager := NewDefaultHookManager()

	// 创建测试钩子
	executed := false
	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		executed = true
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 注册钩子
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	require.NoError(t, err)

	// 创建测试上下文
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	// 执行钩子
	result := manager.ExecuteHook(HookOnRequestReceived, ctx)

	// 验证执行
	assert.True(t, executed)
	assert.NotNil(t, result)
	assert.Equal(t, types.ActionContinue, result.Action)
}

func TestHookExecutionWithNoHooks(t *testing.T) {
	manager := NewDefaultHookManager()

	// 创建测试上下文
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	// 执行钩子（没有注册的钩子）
	result := manager.ExecuteHook(HookOnRequestReceived, ctx)

	// 验证结果
	assert.NotNil(t, result)
	assert.Equal(t, types.ActionContinue, result.Action)
}

func TestHookEnableDisable(t *testing.T) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 注册钩子
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	require.NoError(t, err)

	// 禁用钩子
	err = manager.DisableHook(HookOnRequestReceived, "test_hook")
	assert.NoError(t, err)

	// 验证禁用
	registeredHooks := manager.GetRegisteredHooks(HookOnRequestReceived)
	assert.Len(t, registeredHooks, 1)
	assert.False(t, registeredHooks[0].Enabled)

	// 启用钩子
	err = manager.EnableHook(HookOnRequestReceived, "test_hook")
	assert.NoError(t, err)

	// 验证启用
	registeredHooks = manager.GetRegisteredHooks(HookOnRequestReceived)
	assert.Len(t, registeredHooks, 1)
	assert.True(t, registeredHooks[0].Enabled)
}

func TestHookPriority(t *testing.T) {
	manager := NewDefaultHookManager()

	// 创建多个钩子
	executionOrder := make([]string, 0)

	hook1 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook1")
		return &types.HookResult{Action: types.ActionContinue}
	}

	hook2 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook2")
		return &types.HookResult{Action: types.ActionContinue}
	}

	hook3 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook3")
		return &types.HookResult{Action: types.ActionContinue}
	}

	// 注册钩子（不同的优先级）
	metadata1 := &HookMetadata{Name: "hook1", Priority: 100}
	metadata2 := &HookMetadata{Name: "hook2", Priority: 300}
	metadata3 := &HookMetadata{Name: "hook3", Priority: 200}

	err := manager.Register(HookOnRequestReceived, hook1, metadata1)
	require.NoError(t, err)
	err = manager.Register(HookOnRequestReceived, hook2, metadata2)
	require.NoError(t, err)
	err = manager.Register(HookOnRequestReceived, hook3, metadata3)
	require.NoError(t, err)

	// 创建测试上下文
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	// 执行钩子
	manager.ExecuteHook(HookOnRequestReceived, ctx)

	// 验证执行顺序（按优先级降序）
	assert.Equal(t, []string{"hook2", "hook3", "hook1"}, executionOrder)
}

func TestHookStats(t *testing.T) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 注册钩子
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	require.NoError(t, err)

	// 创建测试上下文
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	// 执行钩子多次
	for i := 0; i < 5; i++ {
		manager.ExecuteHook(HookOnRequestReceived, ctx)
	}

	// 检查统计信息
	stats := manager.GetHookStats()
	assert.Equal(t, 5, stats[HookOnRequestReceived])
}

func TestClearHooks(t *testing.T) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "test_hook",
		Description: "Test hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "test_author",
	}

	// 注册多个钩子
	err := manager.Register(HookOnRequestReceived, hookFunc, metadata)
	require.NoError(t, err)
	err = manager.Register(HookOnResponseReceived, hookFunc, metadata)
	require.NoError(t, err)

	// 验证注册
	assert.Len(t, manager.GetRegisteredHooks(HookOnRequestReceived), 1)
	assert.Len(t, manager.GetRegisteredHooks(HookOnResponseReceived), 1)

	// 清空所有钩子
	manager.Clear()

	// 验证清空
	assert.Len(t, manager.GetRegisteredHooks(HookOnRequestReceived), 0)
	assert.Len(t, manager.GetRegisteredHooks(HookOnResponseReceived), 0)
}

func TestDefaultHookValidator(t *testing.T) {
	validator := NewDefaultHookValidator()

	// 测试有效的钩子函数
	validHook := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	err := validator.ValidateHook(HookOnRequestReceived, validHook)
	assert.NoError(t, err)

	// 测试无效的钩子函数（nil）
	err = validator.ValidateHook(HookOnRequestReceived, nil)
	assert.Error(t, err)

	// 测试无效的钩子函数（非函数类型）
	err = validator.ValidateHook(HookOnRequestReceived, "not a function")
	assert.Error(t, err)

	// 测试有效的元数据
	validMetadata := &HookMetadata{
		Name:    "test_hook",
		Version: "1.0.0",
		Author:  "test_author",
	}

	err = validator.ValidateMetadata(validMetadata)
	assert.NoError(t, err)

	// 测试无效的元数据（nil）
	err = validator.ValidateMetadata(nil)
	assert.Error(t, err)

	// 测试无效的元数据（空名称）
	invalidMetadata := &HookMetadata{
		Name:    "",
		Version: "1.0.0",
		Author:  "test_author",
	}

	err = validator.ValidateMetadata(invalidMetadata)
	assert.Error(t, err)
}

func TestHookChain(t *testing.T) {
	// 创建测试钩子
	executionOrder := make([]string, 0)

	hook1 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook1")
		return &types.HookResult{Action: types.ActionContinue}
	}

	hook2 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook2")
		return &types.HookResult{Action: types.ActionDrop}
	}

	hook3 := func(ctx *types.ProxyContext) *types.HookResult {
		executionOrder = append(executionOrder, "hook3")
		return &types.HookResult{Action: types.ActionContinue}
	}

	// 创建钩子注册
	metadata1 := &HookMetadata{Name: "hook1", Priority: 300}
	metadata2 := &HookMetadata{Name: "hook2", Priority: 200}
	metadata3 := &HookMetadata{Name: "hook3", Priority: 100}

	reg1 := &HookRegistration{Hook: hook1, Metadata: metadata1, Type: HookOnRequestReceived, Enabled: true}
	reg2 := &HookRegistration{Hook: hook2, Metadata: metadata2, Type: HookOnRequestReceived, Enabled: true}
	reg3 := &HookRegistration{Hook: hook3, Metadata: metadata3, Type: HookOnRequestReceived, Enabled: true}

	// 创建钩子链
	hooks := []*HookRegistration{reg1, reg2, reg3}
	executor := NewDefaultHookExecutor()
	chain := NewHookChain(HookOnRequestReceived, hooks, executor)

	// 创建测试上下文
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	// 执行钩子链
	result := chain.Execute(ctx)

	// 验证结果
	assert.Equal(t, types.ActionDrop, result.Action)
	assert.Equal(t, []string{"hook1", "hook2"}, executionOrder) // hook3 不应该执行
}

func BenchmarkHookRegistration(b *testing.B) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "bench_hook",
		Description: "Benchmark hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "bench_author",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hookName := "bench_hook_" + string(rune(i))
		metadata.Name = hookName
		manager.Register(HookOnRequestReceived, hookFunc, metadata)
	}
}

func BenchmarkHookExecution(b *testing.B) {
	manager := NewDefaultHookManager()

	hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
		return &types.HookResult{Action: types.ActionContinue}
	}

	metadata := &HookMetadata{
		Name:        "bench_hook",
		Description: "Benchmark hook",
		Priority:    100,
		Version:     "1.0.0",
		Author:      "bench_author",
	}

	manager.Register(HookOnRequestReceived, hookFunc, metadata)

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx := &types.ProxyContext{
		Request:     req,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn",
		RequestID:   "test-req",
		Metadata:    make(map[string]interface{}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.ExecuteHook(HookOnRequestReceived, ctx)
	}
}