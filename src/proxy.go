package src

import (
	"fmt"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/cert"
	"github.com/mintux/goMitmProxyLib/src/events"
	"github.com/mintux/goMitmProxyLib/src/hooks"
	"github.com/mintux/goMitmProxyLib/src/logger"
	"github.com/mintux/goMitmProxyLib/src/plugins"
	"github.com/mintux/goMitmProxyLib/src/proxy"
	"github.com/mintux/goMitmProxyLib/src/types"
)

// MitmProxy 中间人代理主类
type MitmProxy struct {
	config          *types.Config
	server          proxy.ProxyServer
	certManager     cert.CertificateManager
	hookManager     hooks.HookManager
	eventBus        events.EventBus
	pluginManager   plugins.PluginManager
	logger          logger.Logger
	running         bool
	mu              sync.RWMutex
	shutdownChan    chan struct{}
	wg              sync.WaitGroup
	startTime       time.Time
}

// NewMitmProxy 创建新的中间人代理实例
func NewMitmProxy(config *types.Config) (*MitmProxy, error) {
	if config == nil {
		config = types.DefaultConfig()
	}

	// 创建日志实例
	logConfig := &logger.LogConfig{
		Level:    logger.LogLevel(config.LogLevel),
		Format:   logger.LogFormat(config.LogFormat),
		Output:   config.LogOutput,
		Caller:   true,
		TimeFormat: "2006-01-02 15:04:05.000",
	}

	log, err := logger.NewLogger(logConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// 设置全局日志
	logger.InitGlobalLogger(logConfig)

	proxyInstance := &MitmProxy{
		config:       config,
		logger:       log,
		shutdownChan: make(chan struct{}),
	}

	// 初始化所有组件
	if err := proxyInstance.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return proxyInstance, nil
}

// initializeComponents 初始化所有组件
func (m *MitmProxy) initializeComponents() error {
	var err error

	// 创建事件总线
	m.eventBus = events.NewDefaultEventBus()

	// 创建钩子管理器
	m.hookManager = hooks.NewDefaultHookManager()

	// 创建插件管理器
	m.pluginManager = plugins.NewDefaultPluginManager()

	// 创建证书管理器
	if m.config.EnableHTTPS {
		m.certManager, err = cert.NewDefaultCertificateManager(
			m.config.CACertFile,
			m.config.CAKeyFile,
			"./certs",
		)
		if err != nil {
			return fmt.Errorf("failed to create certificate manager: %w", err)
		}
	}

	// 创建代理服务器
	m.server, err = proxy.NewHTTPProxyServer(m.config)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}

	// 设置组件间的关系
	m.server.SetHookManager(m.hookManager)
	m.server.SetEventBus(m.eventBus)

	return nil
}

// Start 启动代理服务器
func (m *MitmProxy) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("proxy is already running")
	}

	m.logger.Info("Starting GoMitmProxyLib",
		"version", "1.0.0",
		"listen_addr", m.config.ListenAddr,
		"https_enabled", m.config.EnableHTTPS)

	// 扫描插件目录
	if m.config.PluginDir != "" {
		if err := m.pluginManager.ScanPluginDirectory(m.config.PluginDir); err != nil {
			m.logger.Warn("Failed to scan plugin directory", "error", err)
		}
	}

	// 启用配置的插件
	for _, pluginID := range m.config.EnabledPlugins {
		if err := m.pluginManager.EnablePlugin(pluginID); err != nil {
			m.logger.Warn("Failed to enable plugin", "plugin_id", pluginID, "error", err)
		}
	}

	// 启动代理服务器
	if err := m.server.Start(); err != nil {
		return fmt.Errorf("failed to start proxy server: %w", err)
	}

	m.startTime = time.Now()
	m.running = true

	// 启动性能监控
	m.wg.Add(1)
	go m.performanceMonitor()

	m.logger.Info("GoMitmProxyLib started successfully",
		"address", m.server.GetAddr())

	// 发送启动事件
	if m.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventProxyStarted, "proxy-server").
			WithData("address", m.server.GetAddr()).
			WithData("https_enabled", m.config.EnableHTTPS).
			Build()
		m.eventBus.PublishAsync(event)
	}

	return nil
}

// Stop 停止代理服务器
func (m *MitmProxy) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.logger.Info("Stopping GoMitmProxyLib")

	// 发送停止事件
	if m.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventProxyStopped, "proxy-server").
			Build()
		m.eventBus.PublishAsync(event)
	}

	// 发送停止信号
	close(m.shutdownChan)

	// 停止代理服务器
	if err := m.server.Stop(); err != nil {
		m.logger.Warn("Failed to stop proxy server", "error", err)
	}

	// 清理插件
	if err := m.pluginManager.Cleanup(); err != nil {
		m.logger.Warn("Failed to cleanup plugins", "error", err)
	}

	// 停止事件总线
	if err := m.eventBus.Stop(); err != nil {
		m.logger.Warn("Failed to stop event bus", "error", err)
	}

	// 等待所有goroutine结束
	m.wg.Wait()

	m.running = false
	m.logger.Info("GoMitmProxyLib stopped successfully")

	return nil
}

// GetStats 获取统计信息
func (m *MitmProxy) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// 代理服务器统计
	if m.server != nil {
		stats["proxy"] = m.server.GetStats()
	}

	// 钩子统计
	if m.hookManager != nil {
		stats["hooks"] = m.hookManager.GetHookStats()
	}

	// 系统统计
	if m.running {
		stats["uptime"] = time.Since(m.startTime).String()
		stats["start_time"] = m.startTime
	}

	return stats
}

// performanceMonitor 性能监控
func (m *MitmProxy) performanceMonitor() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectMetrics()
		case <-m.shutdownChan:
			return
		}
	}
}

// collectMetrics 收集性能指标
func (m *MitmProxy) collectMetrics() {
	stats := m.GetStats()

	// 记录性能指标
	m.logger.Info("Performance metrics", "stats", stats)

	// 检查健康状态
	healthResults := m.HealthCheck()
	for component, err := range healthResults {
		if err != nil {
			m.logger.Warn("Component health check failed",
				"component", component,
				"error", err)
		}
	}
}

// GetConfig 获取配置
func (m *MitmProxy) GetConfig() *types.Config {
	return m.config
}

// GetLogger 获取日志实例
func (m *MitmProxy) GetLogger() logger.Logger {
	return m.logger
}

// GetEventBus 获取事件总线
func (m *MitmProxy) GetEventBus() events.EventBus {
	return m.eventBus
}

// GetHookManager 获取钩子管理器
func (m *MitmProxy) GetHookManager() hooks.HookManager {
	return m.hookManager
}

// GetPluginManager 获取插件管理器
func (m *MitmProxy) GetPluginManager() plugins.PluginManager {
	return m.pluginManager
}

// GetCertificateManager 获取证书管理器
func (m *MitmProxy) GetCertificateManager() cert.CertificateManager {
	return m.certManager
}

// GetProxyServer 获取代理服务器
func (m *MitmProxy) GetProxyServer() proxy.ProxyServer {
	return m.server
}

// IsRunning 检查是否正在运行
func (m *MitmProxy) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// HealthCheck 健康检查
func (m *MitmProxy) HealthCheck() map[string]error {
	results := make(map[string]error)

	// 检查代理服务器
	if m.server != nil {
		results["proxy_server"] = nil
	} else {
		results["proxy_server"] = fmt.Errorf("proxy server not initialized")
	}

	// 检查事件总线
	if m.eventBus != nil {
		results["event_bus"] = nil
	}

	// 检查钩子管理器
	if m.hookManager != nil {
		results["hook_manager"] = nil
	}

	return results
}

// ReloadConfig 重新加载配置
func (m *MitmProxy) ReloadConfig(newConfig *types.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("cannot reload config while proxy is running")
	}

	m.config = newConfig
	m.logger.Info("Configuration reloaded")

	return nil
}

// GetTLSConfig 获取TLS配置
func (m *MitmProxy) GetTLSConfig() interface{} {
	if m.certManager != nil {
		return m.certManager.(*cert.DefaultCertificateManager).GetTlsConfig()
	}
	return nil
}