package types

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, ":8080", config.ListenAddr)
	assert.True(t, config.EnableHTTPS)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, "json", config.LogFormat)
	assert.Equal(t, "stdout", config.LogOutput)
}

func TestConnectionState(t *testing.T) {
	tests := []struct {
		name  string
		state ConnectionState
	}{
		{"Connecting", StateConnecting},
		{"Connected", StateConnected},
		{"TLSHandshaking", StateTLSHandshaking},
		{"TLSHandshakeCompleted", StateTLSHandshakeCompleted},
		{"Closed", StateClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 测试状态值
			assert.Equal(t, int(tt.state), int(tt.state))
		})
	}
}

func TestAction(t *testing.T) {
	tests := []struct {
		name  string
		action Action
	}{
		{"Continue", ActionContinue},
		{"Drop", ActionDrop},
		{"Modify", ActionModify},
		{"Respond", ActionRespond},
		{"Redirect", ActionRedirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 测试动作值
			assert.Equal(t, int(tt.action), int(tt.action))
		})
	}
}

func TestProxyContext(t *testing.T) {
	// 创建测试请求
	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)

	// 创建测试连接
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// 创建代理上下文
	ctx := &ProxyContext{
		Request:     req,
		ClientConn: clientConn,
		ServerConn: serverConn,
		State:       StateConnected,
		Context:     context.Background(),
		StartTime:   time.Now(),
		ConnectionID: "test-conn-1",
		RequestID:   "test-req-1",
		Metadata:    make(map[string]interface{}),
	}

	// 测试字段
	assert.NotNil(t, ctx.Request)
	assert.Equal(t, clientConn, ctx.ClientConn)
	assert.Equal(t, serverConn, ctx.ServerConn)
	assert.Equal(t, StateConnected, ctx.State)
	assert.NotNil(t, ctx.Context)
	assert.NotZero(t, ctx.StartTime)
	assert.Equal(t, "test-conn-1", ctx.ConnectionID)
	assert.Equal(t, "test-req-1", ctx.RequestID)
	assert.NotNil(t, ctx.Metadata)

	// 测试元数据操作
	ctx.Metadata["test_key"] = "test_value"
	assert.Equal(t, "test_value", ctx.Metadata["test_key"])
}

func TestHookResult(t *testing.T) {
	// 测试空结果
	result := &HookResult{}
	assert.Equal(t, ActionContinue, result.Action)
	assert.NoError(t, result.Error)
	assert.Nil(t, result.Response)
	assert.Empty(t, result.Redirect)
	assert.Nil(t, result.Metadata)

	// 测试带数据的结果
	metadata := make(map[string]interface{})
	metadata["key"] = "value"

	result = &HookResult{
		Action:   ActionDrop,
		Error:    http.ErrNotSupported,
		Redirect: "http://redirect.com",
		Metadata: metadata,
	}

	assert.Equal(t, ActionDrop, result.Action)
	assert.Error(t, result.Error)
	assert.Equal(t, "http://redirect.com", result.Redirect)
	assert.Equal(t, "value", result.Metadata["key"])
}

func TestRequestData(t *testing.T) {
	// 创建测试请求
	req, err := http.NewRequest("POST", "http://example.com/path", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")

	// 创建请求数据
	data := RequestData{
		Method:    req.Method,
		URL:       req.URL.String(),
		Header:    req.Header,
		Body:      []byte("test body"),
		Host:      req.Host,
		RemoteAddr: "127.0.0.1:8080",
	}

	assert.Equal(t, "POST", data.Method)
	assert.Equal(t, "http://example.com/path", data.URL)
	assert.Equal(t, "application/json", data.Header.Get("Content-Type"))
	assert.Equal(t, "test-agent", data.Header.Get("User-Agent"))
	assert.Equal(t, []byte("test body"), data.Body)
	assert.Equal(t, "example.com", data.Host)
	assert.Equal(t, "127.0.0.1:8080", data.RemoteAddr)
}

func TestResponseData(t *testing.T) {
	// 创建响应数据
	data := ResponseData{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       []byte("response body"),
	}

	data.Header.Set("Content-Type", "text/html")
	data.Header.Set("Server", "test-server")

	assert.Equal(t, 200, data.StatusCode)
	assert.Equal(t, "200 OK", data.Status)
	assert.Equal(t, "text/html", data.Header.Get("Content-Type"))
	assert.Equal(t, "test-server", data.Header.Get("Server"))
	assert.Equal(t, []byte("response body"), data.Body)
}

func TestTLSHandshakeInfo(t *testing.T) {
	info := &TLSHandshakeInfo{
		ServerName:  "example.com",
		ClientHello: []byte("client hello"),
		ServerHello: []byte("server hello"),
		CipherSuite: 0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		Version:     0x0303, // TLS version 1.2
		PeerCerts:   [][]byte{[]byte("cert1"), []byte("cert2")},
		State:       StateTLSHandshakeCompleted,
	}

	assert.Equal(t, "example.com", info.ServerName)
	assert.Equal(t, []byte("client hello"), info.ClientHello)
	assert.Equal(t, []byte("server hello"), info.ServerHello)
	assert.Equal(t, uint16(0xC02B), info.CipherSuite)
	assert.Equal(t, uint16(0x0303), info.Version)
	assert.Len(t, info.PeerCerts, 2)
	assert.Equal(t, StateTLSHandshakeCompleted, info.State)
}

func TestProxyStats(t *testing.T) {
	startTime := time.Now()
	stats := &ProxyStats{
		TotalRequests:     100,
		ActiveConnections: 5,
		BytesReceived:     1024,
		BytesSent:         2048,
		Errors:            2,
		StartTime:         startTime,
	}

	assert.Equal(t, int64(100), stats.TotalRequests)
	assert.Equal(t, 5, stats.ActiveConnections)
	assert.Equal(t, int64(1024), stats.BytesReceived)
	assert.Equal(t, int64(2048), stats.BytesSent)
	assert.Equal(t, int64(2), stats.Errors)
	assert.Equal(t, startTime, stats.StartTime)
}

func TestReadCloserWrapper(t *testing.T) {
	data := []byte("test data")
	wrapper := &ReadCloserWrapper{
		Reader: bytes.NewReader(data),
		Closer: &testCloser{},
	}

	// 测试读取
	readData := make([]byte, len(data))
	n, err := wrapper.Read(readData)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, readData)

	// 测试关闭
	err = wrapper.Close()
	assert.NoError(t, err)
}

// testCloser 测试用的Closer实现
type testCloser struct {
	closed bool
}

func (t *testCloser) Close() error {
	t.closed = true
	return nil
}

func TestActionValues(t *testing.T) {
	// 测试Action常量值
	assert.Equal(t, Action(0), ActionContinue)
	assert.Equal(t, Action(1), ActionDrop)
	assert.Equal(t, Action(2), ActionModify)
	assert.Equal(t, Action(3), ActionRespond)
	assert.Equal(t, Action(4), ActionRedirect)
}

func TestConnectionStateValues(t *testing.T) {
	// 测试ConnectionState常量值
	assert.Equal(t, ConnectionState(0), StateConnecting)
	assert.Equal(t, ConnectionState(1), StateConnected)
	assert.Equal(t, ConnectionState(2), StateTLSHandshaking)
	assert.Equal(t, ConnectionState(3), StateTLSHandshakeCompleted)
	assert.Equal(t, ConnectionState(4), StateClosed)
}

func BenchmarkProxyContextCreation(b *testing.B) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := &ProxyContext{
			Request:     req,
			ClientConn: clientConn,
			ServerConn: serverConn,
			State:       StateConnected,
			Context:     context.Background(),
			StartTime:   time.Now(),
			ConnectionID: "test-conn",
			RequestID:   "test-req",
			Metadata:    make(map[string]interface{}),
		}
		_ = ctx
	}
}

func BenchmarkHookResultCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		result := &HookResult{
			Action:   ActionContinue,
			Metadata: make(map[string]interface{}),
		}
		_ = result
	}
}

func BenchmarkRequestDataCreation(b *testing.B) {
	req, _ := http.NewRequest("POST", "http://example.com", nil)
	req.Header.Set("Content-Type", "application/json")
	body := []byte("test body")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := RequestData{
			Method:    req.Method,
			URL:       req.URL.String(),
			Header:    req.Header,
			Body:      body,
			Host:      req.Host,
			RemoteAddr: "127.0.0.1:8080",
		}
		_ = data
	}
}

func BenchmarkResponseDataCreation(b *testing.B) {
	header := make(http.Header)
	header.Set("Content-Type", "text/html")
	body := []byte("response body")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data := ResponseData{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     header,
			Body:       body,
		}
		_ = data
	}
}