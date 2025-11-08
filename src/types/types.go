package types

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// ConnectionState 表示连接的状态
type ConnectionState int

const (
	// StateConnecting 正在连接
	StateConnecting ConnectionState = iota
	// StateConnected 已连接
	StateConnected
	// StateTLSHandshaking TLS握手进行中
	StateTLSHandshaking
	// StateTLSHandshakeCompleted TLS握手完成
	StateTLSHandshakeCompleted
	// StateClosed 连接已关闭
	StateClosed
)

// ProxyContext 代理上下文，包含整个代理处理过程中的所有信息
type ProxyContext struct {
	// 请求信息
	Request *http.Request

	// 响应信息（在处理响应时填充）
	Response *http.Response

	// 连接信息
	ClientConn net.Conn
	ServerConn net.Conn

	// TLS连接信息（HTTPS请求时使用）
	ClientTLSConn *tls.Conn
	ServerTLSConn *tls.Conn

	// 连接状态
	State ConnectionState

	// 上下文
	Context context.Context

	// 错误信息
	Error error

	// 时间戳
	StartTime time.Time
	EndTime   time.Time

	// 连接ID，用于追踪
	ConnectionID string

	// 请求ID，用于追踪
	RequestID string

	// 额外的元数据，用于插件间传递信息
	Metadata map[string]interface{}
}

// Action 表示钩子函数的返回动作
type Action int

const (
	// ActionContinue 继续正常处理
	ActionContinue Action = iota
	// ActionDrop 丢弃请求/响应
	ActionDrop
	// ActionModify 修改请求/响应
	ActionModify
	// ActionRespond 直接响应，不转发到目标服务器
	ActionRespond
	// ActionRedirect 重定向到其他URL
	ActionRedirect
)

// HookResult 钩子函数执行结果
type HookResult struct {
	Action    Action       // 要执行的动作
	Error     error        // 错误信息
	Response  *http.Response // 直接响应的内容（当Action为ActionRespond时使用）
	Redirect  string       // 重定向URL（当Action为ActionRedirect时使用）
	Metadata  map[string]interface{} // 额外的元数据
}

// RequestData 请求数据结构
type RequestData struct {
	Method    string
	URL       string
	Header    http.Header
	Body      []byte
	Host      string
	RemoteAddr string
}

// ResponseData 响应数据结构
type ResponseData struct {
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte
}

// TLSHandshakeInfo TLS握手信息
type TLSHandshakeInfo struct {
	ServerName    string
	ClientHello   []byte
	ServerHello   []byte
	CipherSuite   uint16
	Version       uint16
	PeerCerts     [][]byte
	State         ConnectionState
}

// ProxyStats 代理统计信息
type ProxyStats struct {
	TotalRequests     int64     `json:"total_requests"`
	ActiveConnections int       `json:"active_connections"`
	BytesReceived     int64     `json:"bytes_received"`
	BytesSent         int64     `json:"bytes_sent"`
	Errors            int64     `json:"errors"`
	StartTime         time.Time `json:"start_time"`
}

// Config 代理配置
type Config struct {
	// 监听地址
	ListenAddr string `json:"listen_addr" yaml:"listen_addr"`

	// 是否启用HTTPS代理
	EnableHTTPS bool `json:"enable_https" yaml:"enable_https"`

	// CA证书和密钥路径
	CACertFile string `json:"ca_cert_file" yaml:"ca_cert_file"`
	CAKeyFile  string `json:"ca_key_file" yaml:"ca_key_file"`

	// 超时设置
	ReadTimeout  time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout" yaml:"write_timeout"`

	// 连接池设置
	MaxIdleConns        int           `json:"max_idle_conns" yaml:"max_idle_conns"`
	MaxIdleConnsPerHost int           `json:"max_idle_conns_per_host" yaml:"max_idle_conns_per_host"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`

	// 日志配置
	LogLevel    string `json:"log_level" yaml:"log_level"`
	LogFormat   string `json:"log_format" yaml:"log_format"`
	LogOutput   string `json:"log_output" yaml:"log_output"`

	// 插件配置
	PluginDir   string   `json:"plugin_dir" yaml:"plugin_dir"`
	EnabledPlugins []string `json:"enabled_plugins" yaml:"enabled_plugins"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:          ":8080",
		EnableHTTPS:         true,
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
}

// ReadCloserWrapper 用于包装io.ReadCloser以便多次读取
type ReadCloserWrapper struct {
	Reader io.Reader
	Closer io.Closer
}

func (rw *ReadCloserWrapper) Read(p []byte) (n int, err error) {
	return rw.Reader.Read(p)
}

func (rw *ReadCloserWrapper) Close() error {
	return rw.Closer.Close()
}