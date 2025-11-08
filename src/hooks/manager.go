package hooks

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/logger"
	"github.com/mintux/goMitmProxyLib/src/types"
)

// DefaultHookManager 默认钩子管理器实现
type DefaultHookManager struct {
	hooks       map[HookType][]*HookRegistration
	hooksByName map[string]map[HookType]*HookRegistration
	mu          sync.RWMutex
	executor    HookExecutor
	validator   HookValidator
	logger      logger.Logger
	stats       map[HookType]int
	statsMu     sync.RWMutex
}

// NewDefaultHookManager 创建默认钩子管理器
func NewDefaultHookManager() *DefaultHookManager {
	manager := &DefaultHookManager{
		hooks:       make(map[HookType][]*HookRegistration),
		hooksByName: make(map[string]map[HookType]*HookRegistration),
		executor:    NewDefaultHookExecutor(),
		validator:   NewDefaultHookValidator(),
		logger:      logger.GetGlobalLogger(),
		stats:       make(map[HookType]int),
	}

	return manager
}

// Register 注册钩子
func (m *DefaultHookManager) Register(hookType HookType, hook HookFunc, metadata *HookMetadata) error {
	if metadata == nil {
		metadata = &HookMetadata{
			Name:        "unnamed_hook",
			Description: "No description provided",
			Priority:    0,
			Version:     "1.0.0",
			Author:      "unknown",
		}
	}

	// 验证钩子
	if err := m.validator.ValidateHook(hookType, hook); err != nil {
		return fmt.Errorf("hook validation failed: %w", err)
	}

	if err := m.validator.ValidateMetadata(metadata); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查是否已存在同名钩子
	if hooksByType, exists := m.hooksByName[metadata.Name]; exists {
		if _, exists := hooksByType[hookType]; exists {
			return fmt.Errorf("hook '%s' of type '%s' already registered", metadata.Name, hookType)
		}
	}

	// 创建注册信息
	registration := &HookRegistration{
		Hook:     hook,
		Metadata: metadata,
		Type:     hookType,
		Enabled:  true,
	}

	// 添加到钩子列表
	if m.hooks[hookType] == nil {
		m.hooks[hookType] = make([]*HookRegistration, 0)
	}
	m.hooks[hookType] = append(m.hooks[hookType], registration)

	// 添加到名称索引
	if m.hooksByName[metadata.Name] == nil {
		m.hooksByName[metadata.Name] = make(map[HookType]*HookRegistration)
	}
	m.hooksByName[metadata.Name][hookType] = registration

	// 按优先级排序
	m.sortHooksByPriority(hookType)

	m.logger.Info("Hook registered successfully",
		"name", metadata.Name,
		"type", hookType,
		"priority", metadata.Priority,
		"version", metadata.Version)

	return nil
}

// Unregister 注销钩子
func (m *DefaultHookManager) Unregister(hookType HookType, hookName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 从名称索引中查找
	registration, exists := m.hooksByName[hookName][hookType]
	if !exists {
		return fmt.Errorf("hook '%s' of type '%s' not found", hookName, hookType)
	}

	// 从钩子列表中移除
	hooks := m.hooks[hookType]
	for i, hook := range hooks {
		if hook == registration {
			m.hooks[hookType] = append(hooks[:i], hooks[i+1:]...)
			break
		}
	}

	// 从名称索引中移除
	delete(m.hooksByName[hookName], hookType)
	if len(m.hooksByName[hookName]) == 0 {
		delete(m.hooksByName, hookName)
	}

	m.logger.Info("Hook unregistered successfully",
		"name", hookName,
		"type", hookType)

	return nil
}

// ExecuteHook 执行钩子
func (m *DefaultHookManager) ExecuteHook(hookType HookType, ctx *types.ProxyContext, args ...interface{}) *types.HookResult {
	m.mu.RLock()
	hooks := m.hooks[hookType]
	m.mu.RUnlock()

	if len(hooks) == 0 {
		return &types.HookResult{Action: types.ActionContinue}
	}

	// 更新统计信息
	m.updateStats(hookType)

	// 执行钩子链
	result := m.executor.ExecuteChain(m, hookType, ctx, args...)

	if result != nil && result.Error != nil {
		m.logger.Error("Hook execution error",
			"hook_type", hookType,
			"error", result.Error,
			"request_id", ctx.RequestID)
	}

	return result
}

// EnableHook 启用钩子
func (m *DefaultHookManager) EnableHook(hookType HookType, hookName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	registration, exists := m.hooksByName[hookName][hookType]
	if !exists {
		return fmt.Errorf("hook '%s' of type '%s' not found", hookName, hookType)
	}

	registration.Enabled = true
	m.logger.Info("Hook enabled", "name", hookName, "type", hookType)

	return nil
}

// DisableHook 禁用钩子
func (m *DefaultHookManager) DisableHook(hookType HookType, hookName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	registration, exists := m.hooksByName[hookName][hookType]
	if !exists {
		return fmt.Errorf("hook '%s' of type '%s' not found", hookName, hookType)
	}

	registration.Enabled = false
	m.logger.Info("Hook disabled", "name", hookName, "type", hookType)

	return nil
}

// GetRegisteredHooks 获取已注册的钩子列表
func (m *DefaultHookManager) GetRegisteredHooks(hookType HookType) []*HookRegistration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hooks := make([]*HookRegistration, len(m.hooks[hookType]))
	copy(hooks, m.hooks[hookType])

	return hooks
}

// Clear 清空所有钩子
func (m *DefaultHookManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.hooks = make(map[HookType][]*HookRegistration)
	m.hooksByName = make(map[string]map[HookType]*HookRegistration)

	m.logger.Info("All hooks cleared")
}

// GetHookStats 获取钩子统计信息
func (m *DefaultHookManager) GetHookStats() map[HookType]int {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	stats := make(map[HookType]int)
	for k, v := range m.stats {
		stats[k] = v
	}

	return stats
}

// sortHooksByPriority 按优先级排序钩子
func (m *DefaultHookManager) sortHooksByPriority(hookType HookType) {
	hooks := m.hooks[hookType]
	sort.Slice(hooks, func(i, j int) bool {
		return hooks[i].Metadata.Priority > hooks[j].Metadata.Priority
	})
}

// updateStats 更新统计信息
func (m *DefaultHookManager) updateStats(hookType HookType) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	m.stats[hookType]++
}

// SetExecutor 设置执行器
func (m *DefaultHookManager) SetExecutor(executor HookExecutor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.executor = executor
}

// SetValidator 设置验证器
func (m *DefaultHookManager) SetValidator(validator HookValidator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validator = validator
}

// DefaultHookExecutor 默认钩子执行器
type DefaultHookExecutor struct {
	stopOnFirstAction bool
	parallelExecution bool
	timeout           time.Duration
}

// NewDefaultHookExecutor 创建默认钩子执行器
func NewDefaultHookExecutor() *DefaultHookExecutor {
	return &DefaultHookExecutor{
		stopOnFirstAction: true,
		parallelExecution: false,
		timeout:           30 * time.Second,
	}
}

// Execute 执行单个钩子
func (e *DefaultHookExecutor) Execute(registration *HookRegistration, ctx *types.ProxyContext, args ...interface{}) *types.HookResult {
	if !registration.Enabled {
		return &types.HookResult{Action: types.ActionContinue}
	}

	startTime := time.Now()

	// 使用反射调用钩子函数
	hookValue := reflect.ValueOf(registration.Hook)
	_ = hookValue.Type() // 获取类型但不使用，避免警告

	// 构建参数
	var in []reflect.Value
	in = append(in, reflect.ValueOf(ctx))
	for _, arg := range args {
		in = append(in, reflect.ValueOf(arg))
	}

	// 调用函数
	results := hookValue.Call(in)

	// 解析返回值
	var result *types.HookResult
	if len(results) > 0 {
		if r, ok := results[0].Interface().(*types.HookResult); ok {
			result = r
		}
	}

	if result == nil {
		result = &types.HookResult{Action: types.ActionContinue}
	}

	// 记录执行时间
	duration := time.Since(startTime)
	if duration > e.timeout {
		logger.GetGlobalLogger().Warn("Hook execution timeout",
			"name", registration.Metadata.Name,
			"duration", duration,
			"request_id", ctx.RequestID)
	}

	return result
}

// ExecuteChain 执行钩子链
func (e *DefaultHookExecutor) ExecuteChain(hookManager HookManager, hookType HookType, ctx *types.ProxyContext, args ...interface{}) *types.HookResult {
	// 获取注册的钩子
	hooks := hookManager.GetRegisteredHooks(hookType)

	if len(hooks) == 0 {
		return &types.HookResult{Action: types.ActionContinue}
	}

	var finalResult *types.HookResult

	for _, registration := range hooks {
		if !registration.Enabled {
			continue
		}

		startTime := time.Now()
		result := e.Execute(registration, ctx, args...)
		duration := time.Since(startTime)

		// 记录执行时间
		if duration > e.timeout {
			logger.GetGlobalLogger().Warn("Hook execution timeout",
				"name", registration.Metadata.Name,
				"duration", duration,
				"request_id", ctx.RequestID)
		}

		// 设置最终结果
		if result != nil {
			finalResult = result

			// 如果是停止动作且配置了在第一个非Continue结果时停止，则中断执行
			if result.Action != types.ActionContinue && e.stopOnFirstAction {
				break
			}
		}
	}

	if finalResult == nil {
		finalResult = &types.HookResult{Action: types.ActionContinue}
	}

	return finalResult
}

// SetStopOnFirstAction 设置是否在第一个非Continue结果时停止
func (e *DefaultHookExecutor) SetStopOnFirstAction(stop bool) {
	e.stopOnFirstAction = stop
}

// SetParallelExecution 设置并行执行
func (e *DefaultHookExecutor) SetParallelExecution(parallel bool) {
	e.parallelExecution = parallel
}

// SetTimeout 设置超时时间
func (e *DefaultHookExecutor) SetTimeout(timeout time.Duration) {
	e.timeout = timeout
}

// DefaultHookValidator 默认钩子验证器
type DefaultHookValidator struct {
	logger logger.Logger
}

// NewDefaultHookValidator 创建默认钩子验证器
func NewDefaultHookValidator() *DefaultHookValidator {
	return &DefaultHookValidator{
		logger: logger.GetGlobalLogger(),
	}
}

// ValidateHook 验证钩子函数签名
func (v *DefaultHookValidator) ValidateHook(hookType HookType, hook HookFunc) error {
	if hook == nil {
		return fmt.Errorf("hook function is nil")
	}

	// 使用反射检查函数签名
	hookValue := reflect.ValueOf(hook)
	hookTypeOf := hookValue.Type()

	// 检查是否为函数
	if hookTypeOf.Kind() != reflect.Func {
		return fmt.Errorf("hook must be a function")
	}

	// 检查参数数量（至少有一个ProxyContext参数）
	if hookTypeOf.NumIn() < 1 {
		return fmt.Errorf("hook must have at least one parameter")
	}

	// 检查第一个参数是否为*ProxyContext
	firstParam := hookTypeOf.In(0)
	if firstParam != reflect.TypeOf(&types.ProxyContext{}) {
		return fmt.Errorf("first parameter must be *types.ProxyContext")
	}

	// 检查返回值数量（最多一个返回值）
	if hookTypeOf.NumOut() > 1 {
		return fmt.Errorf("hook can have at most one return value")
	}

	// 检查返回值类型（如果有）
	if hookTypeOf.NumOut() == 1 {
		returnType := hookTypeOf.Out(0)
		if returnType != reflect.TypeOf(&types.HookResult{}) {
			return fmt.Errorf("return value must be *types.HookResult")
		}
	}

	return nil
}

// ValidateMetadata 验证钩子元数据
func (v *DefaultHookValidator) ValidateMetadata(metadata *HookMetadata) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil")
	}

	if metadata.Name == "" {
		return fmt.Errorf("hook name cannot be empty")
	}

	if metadata.Version == "" {
		return fmt.Errorf("hook version cannot be empty")
	}

	if metadata.Author == "" {
		return fmt.Errorf("hook author cannot be empty")
	}

	return nil
}

// HookChain 钩子链
type HookChain struct {
	hooks     []*HookRegistration
	executor  HookExecutor
	hookType  HookType
	logger    logger.Logger
}

// NewHookChain 创建钩子链
func NewHookChain(hookType HookType, hooks []*HookRegistration, executor HookExecutor) *HookChain {
	return &HookChain{
		hooks:    hooks,
		executor: executor,
		hookType: hookType,
		logger:   logger.GetGlobalLogger(),
	}
}

// Execute 执行钩子链
func (c *HookChain) Execute(ctx *types.ProxyContext, args ...interface{}) *types.HookResult {
	var finalResult *types.HookResult

	for _, registration := range c.hooks {
		if !registration.Enabled {
			continue
		}

		startTime := time.Now()
		result := c.executor.Execute(registration, ctx, args...)
		duration := time.Since(startTime)

		c.logger.Debug("Hook executed",
			"name", registration.Metadata.Name,
			"type", c.hookType,
			"action", result.Action,
			"duration", duration,
			"request_id", ctx.RequestID)

		// 设置最终结果
		if result != nil {
			finalResult = result

			// 如果是停止动作且配置了在第一个非Continue结果时停止，则中断执行
			if result.Action != types.ActionContinue {
				break
			}
		}
	}

	if finalResult == nil {
		finalResult = &types.HookResult{Action: types.ActionContinue}
	}

	return finalResult
}

// HookMetrics 钩子指标
type HookMetrics struct {
	ExecutionCount int64         `json:"execution_count"`
	ErrorCount     int64         `json:"error_count"`
	AvgExecutionTime time.Duration `json:"avg_execution_time"`
	MaxExecutionTime time.Duration `json:"max_execution_time"`
	MinExecutionTime time.Duration `json:"min_execution_time"`
	LastExecuted   time.Time     `json:"last_executed"`
}

// GetHookMetrics 获取钩子指标
func (m *DefaultHookManager) GetHookMetrics(hookType HookType, hookName string) (*HookMetrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.hooksByName[hookName][hookType]
	if !exists {
		return nil, fmt.Errorf("hook '%s' of type '%s' not found", hookName, hookType)
	}

	// 这里应该实现实际的指标收集逻辑
	// 简化实现，返回空指标
	return &HookMetrics{}, nil
}