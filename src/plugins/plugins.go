package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"plugin"

	"github.com/mintux/goMitmProxyLib/src/events"
	"github.com/mintux/goMitmProxyLib/src/hooks"
	"github.com/mintux/goMitmProxyLib/src/types"
)

// PluginType 插件类型
type PluginType string

const (
	PluginTypeHook     PluginType = "hook"     // 钩子插件
	PluginTypeFilter   PluginType = "filter"   // 过滤插件
	PluginTypeStorage  PluginType = "storage"  // 存储插件
	PluginTypeMonitor  PluginType = "monitor"  // 监控插件
	PluginTypeAuth     PluginType = "auth"     // 认证插件
	PluginTypeCustom   PluginType = "custom"   // 自定义插件
)

// PluginState 插件状态
type PluginState string

const (
	PluginStateUnloaded PluginState = "unloaded" // 未加载
	PluginStateLoaded   PluginState = "loaded"   // 已加载
	PluginStateActive   PluginState = "active"   // 激活
	PluginStateError    PluginState = "error"    // 错误
	PluginStateDisabled PluginState = "disabled" // 禁用
)

// PluginMetadata 插件元数据
type PluginMetadata struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Author      string      `json:"author"`
	Description string      `json:"description"`
	Homepage    string      `json:"homepage"`
	License     string      `json:"license"`
	Type        PluginType  `json:"type"`
	Tags        []string    `json:"tags"`
	Dependencies []string   `json:"dependencies"`
	Config      interface{} `json:"config"`
}

// Plugin 插件接口
type Plugin interface {
	// 获取插件元数据
	GetMetadata() *PluginMetadata

	// 初始化插件
	Initialize(config map[string]interface{}) error

	// 启动插件
	Start() error

	// 停止插件
	Stop() error

	// 清理资源
	Cleanup() error

	// 获取插件状态
	GetState() PluginState

	// 设置插件状态
	SetState(state PluginState)

	// 获取插件配置
	GetConfig() map[string]interface{}

	// 更新插件配置
	UpdateConfig(config map[string]interface{}) error

	// 健康检查
	HealthCheck() error
}

// HookPlugin 钩子插件接口
type HookPlugin interface {
	Plugin

	// 注册钩子
	RegisterHooks(hookManager hooks.HookManager) error

	// 注销钩子
	UnregisterHooks(hookManager hooks.HookManager) error
}

// EventPlugin 事件插件接口
type EventPlugin interface {
	Plugin

	// 订阅事件
	SubscribeEvents(eventBus events.EventBus) error

	// 取消订阅事件
	UnsubscribeEvents(eventBus events.EventBus) error
}

// FilterPlugin 过滤插件接口
type FilterPlugin interface {
	Plugin

	// 过滤请求
	FilterRequest(ctx *types.ProxyContext) *types.HookResult

	// 过滤响应
	FilterResponse(ctx *types.ProxyContext) *types.HookResult
}

// StoragePlugin 存储插件接口
type StoragePlugin interface {
	Plugin

	// 存储数据
	Store(key string, data []byte) error

	// 获取数据
	Get(key string) ([]byte, error)

	// 删除数据
	Delete(key string) error

	// 查询数据
	Query(pattern string) ([][]byte, error)

	// 存在性检查
	Exists(key string) (bool, error)
}

// MonitorPlugin 监控插件接口
type MonitorPlugin interface {
	Plugin

	// 记录指标
	RecordMetric(name string, value float64, tags map[string]string) error

	// 增加计数器
	IncrementCounter(name string, tags map[string]string) error

	// 设置仪表盘
	SetGauge(name string, value float64, tags map[string]string) error

	// 记录直方图
	RecordHistogram(name string, value float64, tags map[string]string) error

	// 获取指标
	GetMetrics() (map[string]interface{}, error)
}

// PluginConfig 插件配置
type PluginConfig struct {
	Enabled    bool                   `json:"enabled"`
	Config     map[string]interface{} `json:"config"`
	Priority   int                    `json:"priority"`
	AutoStart  bool                   `json:"auto_start"`
	Reloadable bool                   `json:"reloadable"`
}

// PluginManifest 插件清单文件
type PluginManifest struct {
	Metadata    PluginMetadata `json:"metadata"`
	EntryPoint  string         `json:"entry_point"`
	Config      PluginConfig   `json:"config"`
	Resources   []string       `json:"resources"`
	Permissions []string       `json:"permissions"`
}

// PluginManager 插件管理器接口
type PluginManager interface {
	// 加载插件
	LoadPlugin(manifestPath string) error

	// 卸载插件
	UnloadPlugin(pluginID string) error

	// 启用插件
	EnablePlugin(pluginID string) error

	// 禁用插件
	DisablePlugin(pluginID string) error

	// 重启插件
	RestartPlugin(pluginID string) error

	// 获取插件
	GetPlugin(pluginID string) (Plugin, error)

	// 获取所有插件
	GetAllPlugins() map[string]Plugin

	// 获取已启用的插件
	GetEnabledPlugins() []Plugin

	// 获取插件状态
	GetPluginState(pluginID string) PluginState

	// 扫描插件目录
	ScanPluginDirectory(directory string) error

	// 安装插件
	InstallPlugin(source string) error

	// 卸载插件（从磁盘删除）
	UninstallPlugin(pluginID string) error

	// 更新插件
	UpdatePlugin(pluginID string, source string) error

	// 获取插件依赖
	GetDependencies(pluginID string) []string

	// 检查依赖
	CheckDependencies(pluginID string) error

	// 解决依赖
	ResolveDependencies(pluginID string) error

	// 清理所有插件
	Cleanup() error
}

// PluginLoader 插件加载器接口
type PluginLoader interface {
	// 加载插件
	Load(manifest *PluginManifest) (Plugin, error)

	// 卸载插件
	Unload(plugin Plugin) error

	// 验证插件
	Validate(manifest *PluginManifest) error

	// 获取支持的文件类型
	GetSupportedTypes() []string
}

// PluginRegistry 插件注册表接口
type PluginRegistry interface {
	// 注册插件
	Register(plugin Plugin) error

	// 注销插件
	Unregister(pluginID string) error

	// 查找插件
	Find(pluginID string) (Plugin, bool)

	// 列出所有插件
	List() []Plugin

	// 按类型列出插件
	ListByType(pluginType PluginType) []Plugin

	// 按状态列出插件
	ListByState(state PluginState) []Plugin

	// 清空注册表
	Clear()
}

// PluginSecurityManager 插件安全管理器接口
type PluginSecurityManager interface {
	// 验证权限
	ValidatePermissions(plugin Plugin, permissions []string) error

	// 检查沙箱
	CheckSandbox(plugin Plugin) error

	// 设置资源限制
	SetResourceLimits(plugin Plugin, limits map[string]interface{}) error

	// 监控资源使用
	MonitorResourceUsage(plugin Plugin) (map[string]interface{}, error)

	// 终止违规插件
	TerminatePlugin(plugin Plugin, reason string) error
}

// BasePlugin 基础插件实现
type BasePlugin struct {
	metadata *PluginMetadata
	config   map[string]interface{}
	state    PluginState
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewBasePlugin 创建基础插件
func NewBasePlugin(metadata *PluginMetadata) *BasePlugin {
	ctx, cancel := context.WithCancel(context.Background())
	return &BasePlugin{
		metadata: metadata,
		config:   make(map[string]interface{}),
		state:    PluginStateUnloaded,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// GetMetadata 获取插件元数据
func (p *BasePlugin) GetMetadata() *PluginMetadata {
	return p.metadata
}

// Initialize 初始化插件
func (p *BasePlugin) Initialize(config map[string]interface{}) error {
	p.config = config
	p.state = PluginStateLoaded
	return nil
}

// Start 启动插件
func (p *BasePlugin) Start() error {
	p.state = PluginStateActive
	return nil
}

// Stop 停止插件
func (p *BasePlugin) Stop() error {
	p.state = PluginStateLoaded
	return nil
}

// Cleanup 清理资源
func (p *BasePlugin) Cleanup() error {
	p.cancel()
	p.state = PluginStateUnloaded
	return nil
}

// GetState 获取插件状态
func (p *BasePlugin) GetState() PluginState {
	return p.state
}

// SetState 设置插件状态
func (p *BasePlugin) SetState(state PluginState) {
	p.state = state
}

// GetConfig 获取插件配置
func (p *BasePlugin) GetConfig() map[string]interface{} {
	return p.config
}

// UpdateConfig 更新插件配置
func (p *BasePlugin) UpdateConfig(config map[string]interface{}) error {
	p.config = config
	return nil
}

// HealthCheck 健康检查
func (p *BasePlugin) HealthCheck() error {
	if p.state == PluginStateError {
		return fmt.Errorf("plugin is in error state")
	}
	return nil
}

// GetContext 获取插件上下文
func (p *BasePlugin) GetContext() context.Context {
	return p.ctx
}

// LoadPluginManifest 加载插件清单
func LoadPluginManifest(manifestPath string) (*PluginManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest PluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest file: %w", err)
	}

	return &manifest, nil
}

// SavePluginManifest 保存插件清单
func SavePluginManifest(manifest *PluginManifest, manifestPath string) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}

	return nil
}

// ValidatePluginManifest 验证插件清单
func ValidatePluginManifest(manifest *PluginManifest) error {
	if manifest.Metadata.ID == "" {
		return fmt.Errorf("plugin ID is required")
	}

	if manifest.Metadata.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if manifest.Metadata.Version == "" {
		return fmt.Errorf("plugin version is required")
	}

	if manifest.EntryPoint == "" {
		return fmt.Errorf("entry point is required")
	}

	return nil
}

// GoPluginLoader Go插件加载器
type GoPluginLoader struct {
	loadedPlugins map[string]*plugin.Plugin
}

// NewGoPluginLoader 创建Go插件加载器
func NewGoPluginLoader() *GoPluginLoader {
	return &GoPluginLoader{
		loadedPlugins: make(map[string]*plugin.Plugin),
	}
}

// Load 加载Go插件
func (l *GoPluginLoader) Load(manifest *PluginManifest) (Plugin, error) {
	pluginPath := filepath.Join(filepath.Dir(manifest.EntryPoint), manifest.Metadata.ID+".so")

	p, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}

	symbol, err := p.Lookup("NewPlugin")
	if err != nil {
		return nil, fmt.Errorf("failed to lookup NewPlugin symbol: %w", err)
	}

	newPluginFunc, ok := symbol.(func() Plugin)
	if !ok {
		return nil, fmt.Errorf("invalid NewPlugin signature")
	}

	pluginInstance := newPluginFunc()
	l.loadedPlugins[manifest.Metadata.ID] = p

	return pluginInstance, nil
}

// Unload 卸载Go插件
func (l *GoPluginLoader) Unload(plugin Plugin) error {
	pluginID := plugin.GetMetadata().ID
	if _, exists := l.loadedPlugins[pluginID]; exists {
		// Go插件无法直接卸载，只能从内存中移除引用
		delete(l.loadedPlugins, pluginID)
	}
	return nil
}

// Validate 验证Go插件
func (l *GoPluginLoader) Validate(manifest *PluginManifest) error {
	pluginPath := filepath.Join(filepath.Dir(manifest.EntryPoint), manifest.Metadata.ID+".so")

	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file not found: %s", pluginPath)
	}

	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	_, err = p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("failed to lookup NewPlugin symbol: %w", err)
	}

	return nil
}

// GetSupportedTypes 获取支持的文件类型
func (l *GoPluginLoader) GetSupportedTypes() []string {
	return []string{".so"}
}