package utils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// IDGenerator ID生成器接口
type IDGenerator interface {
	Generate() string
	GenerateWithPrefix(prefix string) string
}

// DefaultIDGenerator 默认ID生成器
type DefaultIDGenerator struct {
	counter int64
}

// NewDefaultIDGenerator 创建默认ID生成器
func NewDefaultIDGenerator() *DefaultIDGenerator {
	return &DefaultIDGenerator{}
}

// Generate 生成ID
func (g *DefaultIDGenerator) Generate() string {
	timestamp := time.Now().UnixNano()
	counter := atomic.AddInt64(&g.counter, 1)
	return fmt.Sprintf("%d_%d", timestamp, counter)
}

// GenerateWithPrefix 生成带前缀的ID
func (g *DefaultIDGenerator) GenerateWithPrefix(prefix string) string {
	return prefix + g.Generate()
}

// RandomString 生成随机字符串
func RandomString(length int) string {
	if length <= 0 {
		return ""
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	rand.Read(bytes)

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes)
}

// GenerateRandomHex 生成随机十六进制字符串
func GenerateRandomHex(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// IsValidURL 检查是否为有效URL
func IsValidURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	return parsedURL.Scheme != "" && parsedURL.Host != ""
}

// NormalizeURL 规范化URL
func NormalizeURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// 确保方案存在
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "http"
	}

	// 规范化主机
	parsedURL.Host = strings.ToLower(parsedURL.Host)

	// 移除默认端口
	if parsedURL.Scheme == "http" && strings.HasSuffix(parsedURL.Host, ":80") {
		parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":80")
	} else if parsedURL.Scheme == "https" && strings.HasSuffix(parsedURL.Host, ":443") {
		parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ":443")
	}

	return parsedURL.String(), nil
}

// ExtractHost 从URL中提取主机
func ExtractHost(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return parsedURL.Host, nil
}

// GetClientIP 获取客户端真实IP
func GetClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// 取第一个IP
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// 检查X-Real-IP头
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// 从RemoteAddr获取
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}

// IsLocalIP 检查是否为本地IP
func IsLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查本地回环地址
	if parsedIP.IsLoopback() {
		return true
	}

	// 检查本地链路地址
	if parsedIP.IsLinkLocalUnicast() {
		return true
	}

	// 检查私有网络地址
	if parsedIP.IsPrivate() {
		return true
	}

	return false
}

// CopyReader 复制Reader内容
func CopyReader(src io.Reader) ([]byte, error) {
	if src == nil {
		return nil, nil
	}

	return io.ReadAll(src)
}

// CopyReaderWithLimit 复制Reader内容，限制大小
func CopyReaderWithLimit(src io.Reader, limit int64) ([]byte, error) {
	if src == nil {
		return nil, nil
	}

	limitedReader := io.LimitReader(src, limit)
	return io.ReadAll(limitedReader)
}

// NewReadCloser 从字节数组创建ReadCloser
func NewReadCloser(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}

// IsWebSocketRequest 检查是否为WebSocket请求
func IsWebSocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}

	// 检查Upgrade头
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		return true
	}

	// 检查Connection头
	connection := strings.ToLower(r.Header.Get("Connection"))
	return strings.Contains(connection, "upgrade")
}

// IsHTTP2Request 检查是否为HTTP/2请求
func IsHTTP2Request(r *http.Request) bool {
	if r == nil {
		return false
	}

	return r.Proto == "HTTP/2.0"
}

// ParseContentType 解析Content-Type
func ParseContentType(contentType string) (string, map[string]string, error) {
	if contentType == "" {
		return "", nil, nil
	}

	parts := strings.SplitN(contentType, ";", 2)
	mimeType := strings.TrimSpace(parts[0])

	params := make(map[string]string)
	if len(parts) == 2 {
		paramParts := strings.Split(parts[1], ";")
		for _, param := range paramParts {
			keyValue := strings.SplitN(strings.TrimSpace(param), "=", 2)
			if len(keyValue) == 2 {
				params[strings.TrimSpace(keyValue[0])] = strings.Trim(strings.TrimSpace(keyValue[1]), `"`)
			}
		}
	}

	return mimeType, params, nil
}

// DetectContentEncoding 检测内容编码
func DetectContentEncoding(headers http.Header) string {
	encoding := headers.Get("Content-Encoding")
	if encoding == "" {
		encoding = headers.Get("Transfer-Encoding")
	}
	return strings.ToLower(encoding)
}

// DecompressContent 解压缩内容（简化实现）
func DecompressContent(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip", "x-gzip":
		// 这里应该实现gzip解压缩
		return data, nil
	case "deflate":
		// 这里应该实现deflate解压缩
		return data, nil
	case "br":
		// 这里应该实现brotli解压缩
		return data, nil
	default:
		return data, nil
	}
}

// CompressContent 压缩内容（简化实现）
func CompressContent(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip", "x-gzip":
		// 这里应该实现gzip压缩
		return data, nil
	case "deflate":
		// 这里应该实现deflate压缩
		return data, nil
	case "br":
		// 这里应该实现brotli压缩
		return data, nil
	default:
		return data, nil
	}
}

// MatchURLPattern 匹配URL模式
func MatchURLPattern(pattern, url string) bool {
	// 简单的通配符匹配
	if pattern == "*" {
		return true
	}

	// 正则表达式匹配
	if strings.HasPrefix(pattern, "regex:") {
		regexPattern := strings.TrimPrefix(pattern, "regex:")
		matched, err := regexp.MatchString(regexPattern, url)
		if err != nil {
			return false
		}
		return matched
	}

	// 精确匹配
	if pattern == url {
		return true
	}

	// 前缀匹配
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(url, prefix)
	}

	// 后缀匹配
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(url, suffix)
	}

	return false
}

// FilterHeaders 过滤HTTP头
func FilterHeaders(headers http.Header, filterFunc func(string, string) bool) http.Header {
	filtered := make(http.Header)
	for key, values := range headers {
		for _, value := range values {
			if filterFunc(key, value) {
				filtered.Add(key, value)
			}
		}
	}
	return filtered
}

// SanitizeHeaders 清理HTTP头
func SanitizeHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)

	// 要保留的敏感头
	sensitiveHeaders := map[string]bool{
		"authorization":       true,
		"proxy-authorization": true,
		"cookie":             true,
		"set-cookie":         true,
	}

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		for _, value := range values {
			if sensitiveHeaders[lowerKey] {
				sanitized.Add(key, "***REDACTED***")
			} else {
				sanitized.Add(key, value)
			}
		}
	}

	return sanitized
}

// CalculateContentLength 计算内容长度
func CalculateContentLength(data []byte) int64 {
	return int64(len(data))
}

// IsValidUTF8 检查是否为有效的UTF-8
func IsValidUTF8(data []byte) bool {
	return utf8.Valid(data)
}

// GetSystemInfo 获取系统信息
func GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"go_version":   runtime.Version(),
		"go_os":        runtime.GOOS,
		"go_arch":      runtime.GOARCH,
		"num_cpu":      runtime.NumCPU(),
		"num_goroutine": runtime.NumGoroutine(),
	}
}

// ContextWithTimeout 创建带超时的上下文
func ContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// ContextWithDeadline 创建带截止时间的上下文
func ContextWithDeadline(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, deadline)
}

// MergeContexts 合并上下文
func MergeContexts(ctx1, ctx2 context.Context) context.Context {
	if ctx1 == nil {
		return ctx2
	}
	if ctx2 == nil {
		return ctx1
	}

	// 创建一个新的上下文，当任一父上下文取消时取消
	merged, cancel := context.WithCancel(context.Background())

	go func() {
		defer cancel()
		select {
		case <-ctx1.Done():
		case <-ctx2.Done():
		case <-merged.Done():
		}
	}()

	return merged
}

// RateLimiter 速率限制器
type RateLimiter struct {
	rate     float64
	capacity int
	tokens   float64
	last     time.Time
	mu       sync.Mutex
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(rate float64, capacity int) *RateLimiter {
	return &RateLimiter{
		rate:     rate,
		capacity: capacity,
		tokens:   float64(capacity),
		last:     time.Now(),
	}
}

// Allow 检查是否允许
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.tokens += elapsed * rl.rate
	if rl.tokens > float64(rl.capacity) {
		rl.tokens = float64(rl.capacity)
	}
	rl.last = now

	if rl.tokens >= 1 {
		rl.tokens -= 1
		return true
	}

	return false
}

// Wait 等待直到允许
func (rl *RateLimiter) Wait() {
	for !rl.Allow() {
		time.Sleep(time.Millisecond * 10)
	}
}

// ConnectionPool 连接池
type ConnectionPool struct {
	connections chan net.Conn
	factory     func() (net.Conn, error)
	mu          sync.Mutex
}

// NewConnectionPool 创建连接池
func NewConnectionPool(size int, factory func() (net.Conn, error)) *ConnectionPool {
	return &ConnectionPool{
		connections: make(chan net.Conn, size),
		factory:     factory,
	}
}

// Get 获取连接
func (p *ConnectionPool) Get() (net.Conn, error) {
	select {
	case conn := <-p.connections:
		return conn, nil
	default:
		return p.factory()
	}
}

// Put 放回连接
func (p *ConnectionPool) Put(conn net.Conn) {
	select {
	case p.connections <- conn:
	default:
		conn.Close()
	}
}

// Close 关闭连接池
func (p *ConnectionPool) Close() {
	close(p.connections)
	for conn := range p.connections {
		conn.Close()
	}
}

// RetryConfig 重试配置
type RetryConfig struct {
	MaxRetries int
	Delay      time.Duration
	Backoff    float64
}

// DefaultRetryConfig 默认重试配置
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries: 3,
		Delay:      100 * time.Millisecond,
		Backoff:    2.0,
	}
}

// Retry 重试函数
func Retry(fn func() error, config *RetryConfig) error {
	if config == nil {
		config = DefaultRetryConfig()
	}

	var lastErr error
	delay := config.Delay

	for i := 0; i <= config.MaxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
			if i < config.MaxRetries {
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * config.Backoff)
			}
		}
	}

	return lastErr
}

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	maxFailures   int
	resetTimeout  time.Duration
	failures      int
	lastFailTime  time.Time
	state         string // "closed", "open", "half-open"
	mu            sync.Mutex
}

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        "closed",
	}
}

// Call 调用函数
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// 检查是否需要重置
	if cb.state == "open" && time.Since(cb.lastFailTime) > cb.resetTimeout {
		cb.state = "half-open"
		cb.failures = 0
	}

	// 检查熔断器状态
	if cb.state == "open" {
		return fmt.Errorf("circuit breaker is open")
	}

	// 执行函数
	err := fn()
	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()

		if cb.failures >= cb.maxFailures {
			cb.state = "open"
		}

		return err
	}

	// 成功时重置
	cb.failures = 0
	cb.state = "closed"

	return nil
}

// GetState 获取熔断器状态
func (cb *CircuitBreaker) GetState() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// GetFailures 获取失败次数
func (cb *CircuitBreaker) GetFailures() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures
}