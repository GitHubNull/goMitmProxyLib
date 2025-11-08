package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mintux/goMitmProxyLib/src/events"
	"github.com/mintux/goMitmProxyLib/src/hooks"
	"github.com/mintux/goMitmProxyLib/src/logger"
	"github.com/mintux/goMitmProxyLib/src/types"
)

// ProxyServer 代理服务器接口
type ProxyServer interface {
	// 启动代理服务器
	Start() error

	// 停止代理服务器
	Stop() error

	// 获取服务器地址
	GetAddr() string

	// 获取统计信息
	GetStats() *types.ProxyStats

	// 设置钩子管理器
	SetHookManager(hookManager hooks.HookManager)

	// 设置事件总线
	SetEventBus(eventBus events.EventBus)

	// 获取配置
	GetConfig() *types.Config
}

// HTTPProxyServer HTTP代理服务器实现
type HTTPProxyServer struct {
	config      *types.Config
	server      *http.Server
	listener    net.Listener
	stats       *types.ProxyStats
	logger      logger.Logger
	hookManager hooks.HookManager
	eventBus    events.EventBus
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	// 连接池
	transport    *http.Transport
	connections  sync.Map // 存储活跃连接
	connCounter  int64    // 连接计数器
	requestCounter int64  // 请求计数器

	// TLS配置（用于HTTPS代理）
	tlsConfig *tls.Config
}

// NewHTTPProxyServer 创建HTTP代理服务器
func NewHTTPProxyServer(config *types.Config) (*HTTPProxyServer, error) {
	if config == nil {
		config = types.DefaultConfig()
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())

	// 创建日志实例
	logConfig := &logger.LogConfig{
		Level:  logger.LogLevel(config.LogLevel),
		Format: logger.LogFormat(config.LogFormat),
		Output: config.LogOutput,
	}
	log, err := logger.NewLogger(logConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// 创建传输客户端
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   config.ReadTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	server := &HTTPProxyServer{
		config:     config,
		logger:     log,
		transport:  transport,
		ctx:        ctx,
		cancel:     cancel,
		stats: &types.ProxyStats{
			StartTime: time.Now(),
		},
	}

	// 创建HTTP服务器
	server.server = &http.Server{
		Addr:         config.ListenAddr,
		Handler:      server,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		IdleTimeout:  60 * time.Second,
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}

	return server, nil
}

// Start 启动代理服务器
func (s *HTTPProxyServer) Start() error {
	s.logger.Info("Starting HTTP proxy server",
		"address", s.config.ListenAddr,
		"https_enabled", s.config.EnableHTTPS)

	// 创建监听器
	listener, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.config.ListenAddr, err)
	}
	s.listener = listener

	// 启动事件
	if s.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventProxyStarted, "proxy-server").
			WithData("address", s.config.ListenAddr).
			Build()
		s.eventBus.PublishAsync(event)
	}

	// 启动服务器
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Proxy server error", "error", err)
		}
	}()

	s.logger.Info("HTTP proxy server started successfully", "address", s.listener.Addr())
	return nil
}

// Stop 停止代理服务器
func (s *HTTPProxyServer) Stop() error {
	s.logger.Info("Stopping HTTP proxy server")

	// 发送停止事件
	if s.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventProxyStopped, "proxy-server").
			Build()
		s.eventBus.PublishAsync(event)
	}

	// 取消上下文
	s.cancel()

	// 关闭服务器
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Error("Error shutting down server", "error", err)
		}
	}

	// 关闭监听器
	if s.listener != nil {
		s.listener.Close()
	}

	// 关闭所有活跃连接
	s.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	// 等待所有goroutine结束
	s.wg.Wait()

	s.logger.Info("HTTP proxy server stopped")
	return nil
}

// ServeHTTP 实现http.Handler接口
func (s *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// 生成请求ID
	requestID := s.generateRequestID()

	// 创建代理上下文
	proxyCtx := &types.ProxyContext{
		Request:     r,
		Context:     s.ctx,
		StartTime:   startTime,
		ConnectionID: s.generateConnectionID(),
		RequestID:   requestID,
		Metadata:    make(map[string]interface{}),
	}

	// 更新统计信息
	s.stats.TotalRequests++
	atomic.AddInt64(&s.requestCounter, 1)

	// 记录请求事件
	if s.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventRequestReceived, "proxy-server").
			WithProxyContext(proxyCtx).
			Build()
		s.eventBus.PublishAsync(event)
	}

	// 执行请求钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnRequestReceived, proxyCtx)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 根据请求方法处理
	switch r.Method {
	case http.MethodConnect:
		// CONNECT方法，直接传递给HTTPS处理器处理
		s.handleHTTPSConnect(w, r, proxyCtx)
	default:
		// 普通HTTP请求，不进行hijack
		s.handleHTTPRequest(w, r, proxyCtx)
	}

	// 更新结束时间和统计信息
	proxyCtx.EndTime = time.Now()
	if proxyCtx.Error != nil {
		s.stats.Errors++
	}
}

// handleHTTPRequest 处理HTTP请求
func (s *HTTPProxyServer) handleHTTPRequest(w http.ResponseWriter, r *http.Request, proxyCtx *types.ProxyContext) {
	// 执行请求头钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnRequestHeader, proxyCtx)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 修改请求URL为完整URL
	if !strings.HasPrefix(r.URL.String(), "http") {
		r.URL.Scheme = "http"
		r.URL.Host = r.Host
	}

	// 读取请求体
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	// 执行请求体钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnRequestBody, proxyCtx, bodyBytes)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 发送请求到目标服务器
	resp, err := s.transport.RoundTrip(r)
	if err != nil {
		proxyCtx.Error = err
		s.logger.Error("Failed to proxy request",
			"url", r.URL.String(),
			"error", err,
			"request_id", proxyCtx.RequestID)

		// 执行错误钩子
		if s.hookManager != nil {
			s.hookManager.ExecuteHook(hooks.HookOnError, proxyCtx, err)
		}

		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	proxyCtx.Response = resp

	// 执行响应头钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnResponseHeader, proxyCtx)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 读取并转发响应体
	var responseBody []byte
	if resp.Body != nil {
		responseBody, _ = io.ReadAll(resp.Body)
	}

	// 执行响应体钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnResponseBody, proxyCtx, responseBody)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 写入响应体
	if len(responseBody) > 0 {
		w.Write(responseBody)
	}

	// 更新统计信息
	s.updateStats(proxyCtx)

	// 发送响应事件
	if s.eventBus != nil {
		event := events.NewProxyEventBuilder(events.EventResponseSent, "proxy-server").
			WithProxyContext(proxyCtx).
			Build()
		s.eventBus.PublishAsync(event)
	}
}

// handleHTTPSConnect 处理HTTPS CONNECT方法
func (s *HTTPProxyServer) handleHTTPSConnect(w http.ResponseWriter, r *http.Request, proxyCtx *types.ProxyContext) {
	if !s.config.EnableHTTPS {
		http.Error(w, "HTTPS proxy not enabled", http.StatusMethodNotAllowed)
		return
	}

	// 执行TLS握手开始钩子
	if s.hookManager != nil {
		result := s.hookManager.ExecuteHook(hooks.HookOnTLSHandshakeStart, proxyCtx)
		if result != nil && result.Action != types.ActionContinue {
			s.handleHookResult(w, r, result)
			return
		}
	}

	// 建立到目标服务器的连接
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	serverConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		proxyCtx.Error = err
		s.logger.Error("Failed to connect to target server",
			"host", host,
			"error", err,
			"request_id", proxyCtx.RequestID)

		if s.hookManager != nil {
			s.hookManager.ExecuteHook(hooks.HookOnError, proxyCtx, err)
		}

		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer serverConn.Close()

	proxyCtx.ServerConn = serverConn

	// 获取客户端连接
	var clientConn net.Conn
	if hijacker, ok := w.(http.Hijacker); ok {
		var conn net.Conn
		var buf *bufio.ReadWriter
		conn, buf, err = hijacker.Hijack()
		if err != nil {
			proxyCtx.Error = err
			s.logger.Error("Failed to hijack connection",
				"error", err,
				"request_id", proxyCtx.RequestID)
			return
		}

		clientConn = conn
		proxyCtx.ClientConn = clientConn
		defer clientConn.Close()

		// 发送200 OK响应给客户端
		_, err = buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		if err != nil {
			s.logger.Error("Failed to write CONNECT response",
				"error", err,
				"request_id", proxyCtx.RequestID)
			return
		}
		buf.Flush()

		// 开始双向数据转发
		s.transferData(clientConn, serverConn, proxyCtx)
	}

	// 执行TLS握手完成钩子
	if s.hookManager != nil {
		handshakeInfo := &types.TLSHandshakeInfo{
			ServerName: host,
			State:      types.StateTLSHandshakeCompleted,
		}
		s.hookManager.ExecuteHook(hooks.HookOnTLSHandshakeComplete, proxyCtx, handshakeInfo)
	}
}

// transferData 转发数据
func (s *HTTPProxyServer) transferData(clientConn, serverConn net.Conn, proxyCtx *types.ProxyContext) {
	var wg sync.WaitGroup
	errorChan := make(chan error, 2)

	// 客户端到服务器的数据转发
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(serverConn, clientConn)
		if err != nil {
			errorChan <- err
		}
	}()

	// 服务器到客户端的数据转发
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, serverConn)
		if err != nil {
			errorChan <- err
		}
	}()

	// 等待传输完成
	wg.Wait()
	close(errorChan)

	// 处理错误
	for err := range errorChan {
		if err != nil && err != io.EOF {
			proxyCtx.Error = err
			if s.hookManager != nil {
				s.hookManager.ExecuteHook(hooks.HookOnError, proxyCtx, err)
			}
		}
	}
}

// handleHookResult 处理钩子结果
func (s *HTTPProxyServer) handleHookResult(w http.ResponseWriter, r *http.Request, result *types.HookResult) {
	switch result.Action {
	case types.ActionDrop:
		// 丢弃请求
		return

	case types.ActionRespond:
		// 直接响应
		if result.Response != nil {
			for key, values := range result.Response.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(result.Response.StatusCode)
			if result.Response.Body != nil {
				io.Copy(w, result.Response.Body)
			}
		}

	case types.ActionRedirect:
		// 重定向
		if result.Redirect != "" {
			http.Redirect(w, r, result.Redirect, http.StatusFound)
		}

	case types.ActionModify:
		// 修改请求/响应（通过钩子已经完成）
		// 继续正常处理流程
	}
}

// updateStats 更新统计信息
func (s *HTTPProxyServer) updateStats(proxyCtx *types.ProxyContext) {
	if proxyCtx.Request != nil {
		// 计算传输字节数（简化实现）
		s.stats.BytesReceived += int64(proxyCtx.Request.ContentLength)
	}

	if proxyCtx.Response != nil {
		s.stats.BytesSent += int64(proxyCtx.Response.ContentLength)
	}
}

// generateRequestID 生成请求ID
func (s *HTTPProxyServer) generateRequestID() string {
	return fmt.Sprintf("req_%d_%d",
		time.Now().UnixNano(),
		atomic.AddInt64(&s.requestCounter, 1))
}

// generateConnectionID 生成连接ID
func (s *HTTPProxyServer) generateConnectionID() string {
	return fmt.Sprintf("conn_%d_%d",
		time.Now().UnixNano(),
		atomic.AddInt64(&s.connCounter, 1))
}

// GetAddr 获取服务器地址
func (s *HTTPProxyServer) GetAddr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.config.ListenAddr
}

// GetStats 获取统计信息
func (s *HTTPProxyServer) GetStats() *types.ProxyStats {
	stats := *s.stats
	stats.ActiveConnections = int(s.countActiveConnections())
	return &stats
}

// SetHookManager 设置钩子管理器
func (s *HTTPProxyServer) SetHookManager(hookManager hooks.HookManager) {
	s.hookManager = hookManager
}

// SetEventBus 设置事件总线
func (s *HTTPProxyServer) SetEventBus(eventBus events.EventBus) {
	s.eventBus = eventBus
}

// GetConfig 获取配置
func (s *HTTPProxyServer) GetConfig() *types.Config {
	return s.config
}

// countActiveConnections 计算活跃连接数
func (s *HTTPProxyServer) countActiveConnections() int64 {
	count := int64(0)
	s.connections.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}