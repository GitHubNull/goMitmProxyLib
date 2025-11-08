package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mintux/goMitmProxyLib/src"
	"github.com/mintux/goMitmProxyLib/src/events"
	"github.com/mintux/goMitmProxyLib/src/types"
)

func main() {
	// 创建代理配置
	config := &types.Config{
		ListenAddr:          ":8080",
		EnableHTTPS:         true,
		CACertFile:          "./certs/ca.crt",
		CAKeyFile:           "./certs/ca.key",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		LogLevel:            "info",
		LogFormat:           "json",
		LogOutput:           "stdout",
		PluginDir:           "./plugins",
		EnabledPlugins:      []string{},
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// 设置钩子函数
	setupHooks(proxy)

	// 启动代理
	if err := proxy.Start(); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}

	fmt.Println("🚀 GoMitmProxyLib started successfully!")
	fmt.Printf("📡 Proxy server listening on: %s\n", config.ListenAddr)
	fmt.Printf("🔒 HTTPS support: %v\n", config.EnableHTTPS)
	fmt.Println("Press Ctrl+C to stop the server")

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\n🛑 Shutting down proxy server...")

	// 停止代理
	if err := proxy.Stop(); err != nil {
		log.Printf("Error stopping proxy: %v", err)
	}

	fmt.Println("✅ Proxy server stopped successfully")
}

// setupHooks 设置钩子函数（简化版本）
func setupHooks(proxy *src.MitmProxy) {
	// 简化版本：只设置事件监听器
	setupEventListeners(proxy)
}

// setupEventListeners 设置事件监听器
func setupEventListeners(proxy *src.MitmProxy) {
	eventBus := proxy.GetEventBus()

	// 创建事件处理器
	requestHandler := &SimpleEventHandler{
		name: "request_logger",
	}

	responseHandler := &SimpleEventHandler{
		name: "response_logger",
	}

	errorHandler := &SimpleEventHandler{
		name: "error_logger",
	}

	// 订阅事件
	eventBus.Subscribe(events.EventRequestReceived, requestHandler)
	eventBus.Subscribe(events.EventResponseSent, responseHandler)
	eventBus.Subscribe(events.EventError, errorHandler)

	fmt.Println("📡 Event listeners configured")
}

// SimpleEventHandler 简单事件处理器
type SimpleEventHandler struct {
	name string
}

func (h *SimpleEventHandler) Handle(event *events.Event) error {
	switch event.Type {
	case events.EventRequestReceived:
		if url, ok := event.Data["url"].(string); ok {
			fmt.Printf("📡 Event: Request received for %s\n", url)
		}
	case events.EventResponseSent:
		if statusCode, ok := event.Data["status_code"].(int); ok {
			fmt.Printf("📡 Event: Response sent with status %d\n", statusCode)
		}
	case events.EventError:
		if errMsg, ok := event.Data["error"].(string); ok {
			fmt.Printf("📡 Event: Error occurred - %s\n", errMsg)
		}
	}
	return nil
}

func (h *SimpleEventHandler) GetID() string {
	return h.name
}

func (h *SimpleEventHandler) GetPriority() int {
	return 100
}

func (h *SimpleEventHandler) IsAsync() bool {
	return false
}