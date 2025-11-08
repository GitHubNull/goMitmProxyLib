package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/events"
	"github.com/mintux/goMitmProxyLib/src/hooks"
	"github.com/mintux/goMitmProxyLib/src/logger"
)

// DefaultPluginManager 默认插件管理器实现
type DefaultPluginManager struct {
	registry    PluginRegistry
	loader      PluginLoader
	config      map[string]*PluginConfig
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	logger      logger.Logger
	hookManager hooks.HookManager
	eventBus    events.EventBus
	security    PluginSecurityManager
	mu          sync.RWMutex
}

// NewDefaultPluginManager 创建默认插件管理器
func NewDefaultPluginManager() *DefaultPluginManager {
	ctx, cancel := context.WithCancel(context.Background())

	manager := &DefaultPluginManager{
		registry: NewDefaultPluginRegistry(),
		loader:   NewGoPluginLoader(),
		config:   make(map[string]*PluginConfig),
		ctx:      ctx,
		cancel:   cancel,
		logger:   logger.GetGlobalLogger(),
		security: NewDefaultPluginSecurityManager(),
	}

	return manager
}

// LoadPlugin 加载插件
func (m *DefaultPluginManager) LoadPlugin(manifestPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 加载插件清单
	manifest, err := LoadPluginManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to load plugin manifest: %w", err)
	}

	// 验证插件清单
	if err := ValidatePluginManifest(manifest); err != nil {
		return fmt.Errorf("invalid plugin manifest: %w", err)
	}

	// 检查依赖
	if err := m.CheckDependencies(manifest.Metadata.ID); err != nil {
		return fmt.Errorf("dependency check failed: %w", err)
	}

	// 检查是否已经加载
	if _, exists := m.registry.Find(manifest.Metadata.ID); exists {
		return fmt.Errorf("plugin '%s' already loaded", manifest.Metadata.ID)
	}

	m.logger.Info("Loading plugin",
		"id", manifest.Metadata.ID,
		"name", manifest.Metadata.Name,
		"version", manifest.Metadata.Version,
		"type", manifest.Metadata.Type)

	// 加载插件
	plugin, err := m.loader.Load(manifest)
	if err != nil {
		return fmt.Errorf("failed to load plugin: %w", err)
	}

	// 初始化插件
	config := manifest.Config.Config
	if err := plugin.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize plugin: %w", err)
	}

	// 安全检查
	if err := m.security.ValidatePermissions(plugin, manifest.Permissions); err != nil {
		plugin.Cleanup()
		return fmt.Errorf("security validation failed: %w", err)
	}

	// 注册插件
	if err := m.registry.Register(plugin); err != nil {
		plugin.Cleanup()
		return fmt.Errorf("failed to register plugin: %w", err)
	}

	// 保存配置
	m.config[manifest.Metadata.ID] = &manifest.Config

	// 如果配置了自动启动，则启动插件
	if manifest.Config.AutoStart {
		if err := m.startPlugin(plugin); err != nil {
			m.registry.Unregister(manifest.Metadata.ID)
			plugin.Cleanup()
			return fmt.Errorf("failed to start plugin: %w", err)
		}
	}

	m.logger.Info("Plugin loaded successfully",
		"id", manifest.Metadata.ID,
		"name", manifest.Metadata.Name)

	// 发送插件加载事件
	if m.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventPluginLoaded, "plugin-manager").
			WithData("plugin_id", manifest.Metadata.ID).
			WithData("plugin_name", manifest.Metadata.Name).
			WithData("plugin_version", manifest.Metadata.Version).
			Build()
		m.eventBus.PublishAsync(event)
	}

	return nil
}

// UnloadPlugin 卸载插件
func (m *DefaultPluginManager) UnloadPlugin(pluginID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.registry.Find(pluginID)
	if !exists {
		return fmt.Errorf("plugin '%s' not found", pluginID)
	}

	m.logger.Info("Unloading plugin", "id", pluginID)

	// 停止插件
	if plugin.GetState() == PluginStateActive {
		if err := plugin.Stop(); err != nil {
			m.logger.Warn("Failed to stop plugin", "id", pluginID, "error", err)
		}
	}

	// 清理插件
	if err := plugin.Cleanup(); err != nil {
		m.logger.Warn("Failed to cleanup plugin", "id", pluginID, "error", err)
	}

	// 从注册表中移除
	if err := m.registry.Unregister(pluginID); err != nil {
		return fmt.Errorf("failed to unregister plugin: %w", err)
	}

	// 卸载加载器
	if err := m.loader.Unload(plugin); err != nil {
		m.logger.Warn("Failed to unload plugin", "id", pluginID, "error", err)
	}

	// 删除配置
	delete(m.config, pluginID)

	m.logger.Info("Plugin unloaded successfully", "id", pluginID)

	// 发送插件卸载事件
	if m.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventPluginUnloaded, "plugin-manager").
			WithData("plugin_id", pluginID).
			Build()
		m.eventBus.PublishAsync(event)
	}

	return nil
}

// EnablePlugin 启用插件
func (m *DefaultPluginManager) EnablePlugin(pluginID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.registry.Find(pluginID)
	if !exists {
		return fmt.Errorf("plugin '%s' not found", pluginID)
	}

	// 检查插件状态
	if plugin.GetState() == PluginStateActive {
		return nil // 已经是激活状态
	}

	if plugin.GetState() != PluginStateLoaded {
		return fmt.Errorf("plugin '%s' is not in loaded state", pluginID)
	}

	m.logger.Info("Enabling plugin", "id", pluginID)

	// 启动插件
	if err := m.startPlugin(plugin); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	m.logger.Info("Plugin enabled successfully", "id", pluginID)
	return nil
}

// DisablePlugin 禁用插件
func (m *DefaultPluginManager) DisablePlugin(pluginID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.registry.Find(pluginID)
	if !exists {
		return fmt.Errorf("plugin '%s' not found", pluginID)
	}

	// 检查插件状态
	if plugin.GetState() != PluginStateActive {
		return nil // 已经是非激活状态
	}

	m.logger.Info("Disabling plugin", "id", pluginID)

	// 停止插件
	if err := plugin.Stop(); err != nil {
		return fmt.Errorf("failed to stop plugin: %w", err)
	}

	m.logger.Info("Plugin disabled successfully", "id", pluginID)
	return nil
}

// RestartPlugin 重启插件
func (m *DefaultPluginManager) RestartPlugin(pluginID string) error {
	// 先禁用
	if err := m.DisablePlugin(pluginID); err != nil {
		return err
	}

	// 等待一小段时间
	time.Sleep(100 * time.Millisecond)

	// 再启用
	return m.EnablePlugin(pluginID)
}

// GetPlugin 获取插件
func (m *DefaultPluginManager) GetPlugin(pluginID string) (Plugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.registry.Find(pluginID)
	if !exists {
		return nil, fmt.Errorf("plugin '%s' not found", pluginID)
	}

	return plugin, nil
}

// GetAllPlugins 获取所有插件
func (m *DefaultPluginManager) GetAllPlugins() map[string]Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make(map[string]Plugin)
	for _, plugin := range m.registry.List() {
		plugins[plugin.GetMetadata().ID] = plugin
	}

	return plugins
}

// GetEnabledPlugins 获取已启用的插件
func (m *DefaultPluginManager) GetEnabledPlugins() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.registry.ListByState(PluginStateActive)
}

// GetPluginState 获取插件状态
func (m *DefaultPluginManager) GetPluginState(pluginID string) PluginState {
	plugin, err := m.GetPlugin(pluginID)
	if err != nil {
		return PluginStateUnloaded
	}

	return plugin.GetState()
}

// ScanPluginDirectory 扫描插件目录
func (m *DefaultPluginManager) ScanPluginDirectory(directory string) error {
	if directory == "" {
		return fmt.Errorf("plugin directory not specified")
	}

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return fmt.Errorf("plugin directory '%s' does not exist", directory)
	}

	m.logger.Info("Scanning plugin directory", "directory", directory)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "plugin.json" {
			m.logger.Debug("Found plugin manifest", "path", path)

			// 异步加载插件
			m.wg.Add(1)
			go func(manifestPath string) {
				defer m.wg.Done()
				if err := m.LoadPlugin(manifestPath); err != nil {
					m.logger.Error("Failed to load plugin",
						"manifest", manifestPath,
						"error", err)
				}
			}(path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to scan plugin directory: %w", err)
	}

	m.logger.Info("Plugin directory scan completed", "directory", directory)
	return nil
}

// InstallPlugin 安装插件
func (m *DefaultPluginManager) InstallPlugin(source string) error {
	// 这里可以实现从URL、文件等源安装插件
	// 简化实现，假设source是本地目录
	return m.ScanPluginDirectory(source)
}

// UninstallPlugin 卸载插件（从磁盘删除）
func (m *DefaultPluginManager) UninstallPlugin(pluginID string) error {
	// 先卸载插件
	if err := m.UnloadPlugin(pluginID); err != nil {
		return err
	}

	// 这里可以添加删除插件文件的逻辑
	// 简化实现，只卸载内存中的插件
	m.logger.Info("Plugin uninstalled", "id", pluginID)
	return nil
}

// UpdatePlugin 更新插件
func (m *DefaultPluginManager) UpdatePlugin(pluginID string, source string) error {
	// 先卸载旧版本
	if err := m.UnloadPlugin(pluginID); err != nil {
		return err
	}

	// 安装新版本
	return m.InstallPlugin(source)
}

// GetDependencies 获取插件依赖
func (m *DefaultPluginManager) GetDependencies(pluginID string) []string {
	plugin, err := m.GetPlugin(pluginID)
	if err != nil {
		return nil
	}

	return plugin.GetMetadata().Dependencies
}

// CheckDependencies 检查依赖
func (m *DefaultPluginManager) CheckDependencies(pluginID string) error {
	dependencies := m.GetDependencies(pluginID)

	for _, dep := range dependencies {
		if _, exists := m.registry.Find(dep); !exists {
			return fmt.Errorf("dependency '%s' not found", dep)
		}
	}

	return nil
}

// ResolveDependencies 解决依赖
func (m *DefaultPluginManager) ResolveDependencies(pluginID string) error {
	return m.CheckDependencies(pluginID)
}

// Cleanup 清理所有插件
func (m *DefaultPluginManager) Cleanup() error {
	m.logger.Info("Cleaning up all plugins")

	// 停止所有插件
	plugins := m.registry.ListByState(PluginStateActive)
	for _, plugin := range plugins {
		if err := plugin.Stop(); err != nil {
			m.logger.Warn("Failed to stop plugin", "id", plugin.GetMetadata().ID, "error", err)
		}
	}

	// 清理所有插件
	allPlugins := m.registry.List()
	for _, plugin := range allPlugins {
		if err := plugin.Cleanup(); err != nil {
			m.logger.Warn("Failed to cleanup plugin", "id", plugin.GetMetadata().ID, "error", err)
		}
	}

	// 清空注册表
	m.registry.Clear()

	// 取消上下文
	m.cancel()

	// 等待所有goroutine结束
	m.wg.Wait()

	m.logger.Info("All plugins cleaned up")
	return nil
}

// startPlugin 启动插件
func (m *DefaultPluginManager) startPlugin(plugin Plugin) error {
	// 根据插件类型进行特殊处理
	switch p := plugin.(type) {
	case HookPlugin:
		if m.hookManager != nil {
			if err := p.RegisterHooks(m.hookManager); err != nil {
				return fmt.Errorf("failed to register hooks: %w", err)
			}
		}
	case EventPlugin:
		if m.eventBus != nil {
			if err := p.SubscribeEvents(m.eventBus); err != nil {
				return fmt.Errorf("failed to subscribe events: %w", err)
			}
		}
	}

	// 启动插件
	if err := plugin.Start(); err != nil {
		return fmt.Errorf("failed to start plugin: %w", err)
	}

	return nil
}

// SetHookManager 设置钩子管理器
func (m *DefaultPluginManager) SetHookManager(hookManager hooks.HookManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hookManager = hookManager
}

// SetEventBus 设置事件总线
func (m *DefaultPluginManager) SetEventBus(eventBus events.EventBus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventBus = eventBus
}

// GetPluginConfig 获取插件配置
func (m *DefaultPluginManager) GetPluginConfig(pluginID string) (*PluginConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config, exists := m.config[pluginID]
	if !exists {
		return nil, fmt.Errorf("config for plugin '%s' not found", pluginID)
	}

	// 返回副本
	configCopy := *config
	return &configCopy, nil
}

// UpdatePluginConfig 更新插件配置
func (m *DefaultPluginManager) UpdatePluginConfig(pluginID string, config map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.registry.Find(pluginID)
	if !exists {
		return fmt.Errorf("plugin '%s' not found", pluginID)
	}

	// 更新配置
	if err := plugin.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to update plugin config: %w", err)
	}

	// 更新内存中的配置
	if m.config[pluginID] != nil {
		m.config[pluginID].Config = config
	}

	m.logger.Info("Plugin config updated", "id", pluginID)
	return nil
}

// HealthCheck 插件健康检查
func (m *DefaultPluginManager) HealthCheck(pluginID string) error {
	plugin, err := m.GetPlugin(pluginID)
	if err != nil {
		return err
	}

	return plugin.HealthCheck()
}

// HealthCheckAll 所有插件健康检查
func (m *DefaultPluginManager) HealthCheckAll() map[string]error {
	results := make(map[string]error)
	plugins := m.GetAllPlugins()

	for id, plugin := range plugins {
		if err := plugin.HealthCheck(); err != nil {
			results[id] = err
		}
	}

	return results
}

// GetPluginStats 获取插件统计信息
func (m *DefaultPluginManager) GetPluginStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]interface{})
	plugins := m.registry.List()

	stats["total_plugins"] = len(plugins)
	stats["active_plugins"] = len(m.registry.ListByState(PluginStateActive))
	stats["loaded_plugins"] = len(m.registry.ListByState(PluginStateLoaded))
	stats["error_plugins"] = len(m.registry.ListByState(PluginStateError))

	// 按类型统计
	typeStats := make(map[PluginType]int)
	for _, plugin := range plugins {
		pluginType := plugin.GetMetadata().Type
		typeStats[pluginType]++
	}
	stats["by_type"] = typeStats

	return stats
}

// DefaultPluginRegistry 默认插件注册表实现
type DefaultPluginRegistry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

// NewDefaultPluginRegistry 创建默认插件注册表
func NewDefaultPluginRegistry() *DefaultPluginRegistry {
	return &DefaultPluginRegistry{
		plugins: make(map[string]Plugin),
	}
}

// Register 注册插件
func (r *DefaultPluginRegistry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pluginID := plugin.GetMetadata().ID
	if _, exists := r.plugins[pluginID]; exists {
		return fmt.Errorf("plugin '%s' already registered", pluginID)
	}

	r.plugins[pluginID] = plugin
	return nil
}

// Unregister 注销插件
func (r *DefaultPluginRegistry) Unregister(pluginID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[pluginID]; !exists {
		return fmt.Errorf("plugin '%s' not found", pluginID)
	}

	delete(r.plugins, pluginID)
	return nil
}

// Find 查找插件
func (r *DefaultPluginRegistry) Find(pluginID string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugin, exists := r.plugins[pluginID]
	return plugin, exists
}

// List 列出所有插件
func (r *DefaultPluginRegistry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]Plugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// ListByType 按类型列出插件
func (r *DefaultPluginRegistry) ListByType(pluginType PluginType) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var plugins []Plugin
	for _, plugin := range r.plugins {
		if plugin.GetMetadata().Type == pluginType {
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

// ListByState 按状态列出插件
func (r *DefaultPluginRegistry) ListByState(state PluginState) []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var plugins []Plugin
	for _, plugin := range r.plugins {
		if plugin.GetState() == state {
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

// Clear 清空注册表
func (r *DefaultPluginRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.plugins = make(map[string]Plugin)
}

// DefaultPluginSecurityManager 默认插件安全管理器实现
type DefaultPluginSecurityManager struct {
	logger logger.Logger
}

// NewDefaultPluginSecurityManager 创建默认插件安全管理器
func NewDefaultPluginSecurityManager() *DefaultPluginSecurityManager {
	return &DefaultPluginSecurityManager{
		logger: logger.GetGlobalLogger(),
	}
}

// ValidatePermissions 验证权限
func (s *DefaultPluginSecurityManager) ValidatePermissions(plugin Plugin, permissions []string) error {
	// 简化实现，只记录日志
	s.logger.Debug("Validating plugin permissions",
		"plugin_id", plugin.GetMetadata().ID,
		"permissions", permissions)

	return nil
}

// CheckSandbox 检查沙箱
func (s *DefaultPluginSecurityManager) CheckSandbox(plugin Plugin) error {
	s.logger.Debug("Checking plugin sandbox", "plugin_id", plugin.GetMetadata().ID)
	return nil
}

// SetResourceLimits 设置资源限制
func (s *DefaultPluginSecurityManager) SetResourceLimits(plugin Plugin, limits map[string]interface{}) error {
	s.logger.Debug("Setting resource limits",
		"plugin_id", plugin.GetMetadata().ID,
		"limits", limits)

	return nil
}

// MonitorResourceUsage 监控资源使用
func (s *DefaultPluginSecurityManager) MonitorResourceUsage(plugin Plugin) (map[string]interface{}, error) {
	s.logger.Debug("Monitoring resource usage", "plugin_id", plugin.GetMetadata().ID)

	// 返回模拟的资源使用情况
	return map[string]interface{}{
		"memory_usage": "10MB",
		"cpu_usage":    "5%",
		"goroutines":   3,
	}, nil
}

// TerminatePlugin 终止违规插件
func (s *DefaultPluginSecurityManager) TerminatePlugin(plugin Plugin, reason string) error {
	s.logger.Warn("Terminating plugin",
		"plugin_id", plugin.GetMetadata().ID,
		"reason", reason)

	return plugin.Stop()
}