package events

import (
	"context"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/types"
)

// EventType 事件类型
type EventType string

const (
	// 连接事件
	EventClientConnected    EventType = "client_connected"
	EventClientDisconnected EventType = "client_disconnected"
	EventServerConnected    EventType = "server_connected"
	EventServerDisconnected EventType = "server_disconnected"

	// TLS事件
	EventTLSHandshakeStart      EventType = "tls_handshake_start"
	EventTLSHandshakeComplete   EventType = "tls_handshake_complete"
	EventTLSCertificateGenerated EventType = "tls_certificate_generated"

	// HTTP事件
	EventRequestReceived  EventType = "request_received"
	EventRequestProcessed EventType = "request_processed"
	EventResponseReceived EventType = "response_received"
	EventResponseSent     EventType = "response_sent"

	// 数据事件
	EventDataUpload   EventType = "data_upload"
	EventDataDownload EventType = "data_download"

	// 错误事件
	EventError       EventType = "error"
	EventPanic       EventType = "panic"
	EventWarning     EventType = "warning"

	// 系统事件
	EventProxyStarted EventType = "proxy_started"
	EventProxyStopped EventType = "proxy_stopped"
	EventPluginLoaded EventType = "plugin_loaded"
	EventPluginUnloaded EventType = "plugin_unloaded"
)

// Event 事件结构
type Event struct {
	Type      EventType               `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Context   context.Context        `json:"-"`
	Source    string                 `json:"source"` // 事件源
	ID        string                 `json:"id"`     // 事件ID
}

// EventHandler 事件处理器接口
type EventHandler interface {
	Handle(event *Event) error
	GetID() string
	GetPriority() int
	IsAsync() bool
}

// EventMiddleware 事件中间件接口
type EventMiddleware interface {
	Process(event *Event, next EventHandler) error
	GetOrder() int // 执行顺序
}

// EventBus 事件总线接口
type EventBus interface {
	// 订阅事件
	Subscribe(eventType EventType, handler EventHandler) error

	// 取消订阅
	Unsubscribe(eventType EventType, handlerID string) error

	// 发布事件（同步）
	Publish(event *Event) error

	// 发布事件（异步）
	PublishAsync(event *Event) error

	// 批量发布事件
	PublishBatch(events []*Event) error

	// 添加中间件
	AddMiddleware(middleware EventMiddleware) error

	// 移除中间件
	RemoveMiddleware(middlewareID string) error

	// 获取订阅者数量
	GetSubscriberCount(eventType EventType) int

	// 获取所有事件类型
	GetEventTypes() []EventType

	// 清空所有订阅
	Clear()

	// 停止事件总线
	Stop() error
}

// EventFilter 事件过滤器接口
type EventFilter interface {
	Match(event *Event) bool
	GetDescription() string
}

// EventStore 事件存储接口（用于事件溯源）
type EventStore interface {
	// 存储事件
	Store(event *Event) error

	// 获取事件
	Get(eventID string) (*Event, error)

	// 根据条件查询事件
	Query(filter EventFilter, limit, offset int) ([]*Event, error)

	// 根据时间范围查询事件
	QueryByTimeRange(start, end time.Time, limit, offset int) ([]*Event, error)

	// 根据事件类型查询事件
	QueryByType(eventType EventType, limit, offset int) ([]*Event, error)

	// 删除事件
	Delete(eventID string) error

	// 清空旧事件
	CleanOldEvents(olderThan time.Time) error

	// 获取事件总数
	Count(filter EventFilter) (int64, error)
}

// EventSerializer 事件序列化接口
type EventSerializer interface {
	// 序列化事件
	Serialize(event *Event) ([]byte, error)

	// 反序列化事件
	Deserialize(data []byte) (*Event, error)

	// 获取格式类型
	GetFormat() string
}

// EventMetrics 事件指标接口
type EventMetrics interface {
	// 记录事件处理时间
	RecordProcessingTime(eventType EventType, duration time.Duration)

	// 记录事件处理错误
	RecordError(eventType EventType, err error)

	// 获取事件处理统计
	GetStats(eventType EventType) *EventStats

	// 获取所有事件统计
	GetAllStats() map[EventType]*EventStats

	// 重置统计
	Reset()
}

// EventStats 事件统计信息
type EventStats struct {
	EventType        EventType     `json:"event_type"`
	TotalEvents      int64         `json:"total_events"`
	SuccessEvents    int64         `json:"success_events"`
	ErrorEvents      int64         `json:"error_events"`
	AvgProcessingTime time.Duration `json:"avg_processing_time"`
	MaxProcessingTime time.Duration `json:"max_processing_time"`
	MinProcessingTime time.Duration `json:"min_processing_time"`
	LastProcessed    time.Time     `json:"last_processed"`
}

// ProxyEventBuilder 代理事件构建器
type ProxyEventBuilder struct {
	eventType EventType
	source    string
	timestamp time.Time
	data      map[string]interface{}
	context   context.Context
}

// NewProxyEventBuilder 创建代理事件构建器
func NewProxyEventBuilder(eventType EventType, source string) *ProxyEventBuilder {
	return &ProxyEventBuilder{
		eventType: eventType,
		source:    source,
		timestamp: time.Now(),
		data:      make(map[string]interface{}),
		context:   context.Background(),
	}
}

// WithContext 设置上下文
func (b *ProxyEventBuilder) WithContext(ctx context.Context) *ProxyEventBuilder {
	b.context = ctx
	return b
}

// WithProxyContext 设置代理上下文
func (b *ProxyEventBuilder) WithProxyContext(proxyCtx *types.ProxyContext) *ProxyEventBuilder {
	b.data["connection_id"] = proxyCtx.ConnectionID
	b.data["request_id"] = proxyCtx.RequestID

	// 安全地获取客户端地址
	if proxyCtx.ClientConn != nil {
		b.data["client_addr"] = proxyCtx.ClientConn.RemoteAddr().String()
	} else if proxyCtx.Request != nil {
		b.data["client_addr"] = proxyCtx.Request.RemoteAddr
	}

	if proxyCtx.Request != nil {
		b.data["method"] = proxyCtx.Request.Method
		b.data["url"] = proxyCtx.Request.URL.String()
		b.data["host"] = proxyCtx.Request.Host
		b.data["user_agent"] = proxyCtx.Request.Header.Get("User-Agent")
	}

	if proxyCtx.Response != nil {
		b.data["status_code"] = proxyCtx.Response.StatusCode
		b.data["response_size"] = proxyCtx.Response.ContentLength
	}

	if proxyCtx.Error != nil {
		b.data["error"] = proxyCtx.Error.Error()
	}

	return b
}

// WithData 添加数据
func (b *ProxyEventBuilder) WithData(key string, value interface{}) *ProxyEventBuilder {
	b.data[key] = value
	return b
}

// WithTimestamp 设置时间戳
func (b *ProxyEventBuilder) WithTimestamp(timestamp time.Time) *ProxyEventBuilder {
	b.timestamp = timestamp
	return b
}

// Build 构建事件
func (b *ProxyEventBuilder) Build() *Event {
	return &Event{
		Type:      b.eventType,
		Timestamp: b.timestamp,
		Data:      b.data,
		Context:   b.context,
		Source:    b.source,
		ID:        generateEventID(),
	}
}

// generateEventID 生成事件ID
func generateEventID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString 生成随机字符串
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// AsyncEventHandler 异步事件处理器
type AsyncEventHandler struct {
	handler   EventHandler
	eventChan chan *Event
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// NewAsyncEventHandler 创建异步事件处理器
func NewAsyncEventHandler(handler EventHandler, bufferSize int) *AsyncEventHandler {
	return &AsyncEventHandler{
		handler:   handler,
		eventChan: make(chan *Event, bufferSize),
		stopChan:  make(chan struct{}),
	}
}

// Start 启动异步处理器
func (h *AsyncEventHandler) Start() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			select {
			case event := <-h.eventChan:
				h.handler.Handle(event)
			case <-h.stopChan:
				return
			}
		}
	}()
}

// Stop 停止异步处理器
func (h *AsyncEventHandler) Stop() {
	close(h.stopChan)
	h.wg.Wait()
}

// Handle 处理事件
func (h *AsyncEventHandler) Handle(event *Event) error {
	select {
	case h.eventChan <- event:
		return nil
	default:
		// 如果通道满了，直接同步处理
		return h.handler.Handle(event)
	}
}

func (h *AsyncEventHandler) GetID() string {
	return h.handler.GetID()
}

func (h *AsyncEventHandler) GetPriority() int {
	return h.handler.GetPriority()
}

func (h *AsyncEventHandler) IsAsync() bool {
	return true
}