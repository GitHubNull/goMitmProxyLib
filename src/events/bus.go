package events

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mintux/goMitmProxyLib/src/logger"
)

// DefaultEventBus 默认事件总线实现
type DefaultEventBus struct {
	subscribers map[EventType][]*eventSubscription
	mu          sync.RWMutex
	middleware  []EventMiddleware
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	logger      logger.Logger
	metrics     EventMetrics
}

type eventSubscription struct {
	handler EventHandler
	active  bool
}

// NewDefaultEventBus 创建默认事件总线
func NewDefaultEventBus() EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	bus := &DefaultEventBus{
		subscribers: make(map[EventType][]*eventSubscription),
		middleware:  make([]EventMiddleware, 0),
		running:     true,
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger.GetGlobalLogger(),
		metrics:     NewDefaultEventMetrics(),
	}
	return bus
}

// Subscribe 订阅事件
func (bus *DefaultEventBus) Subscribe(eventType EventType, handler EventHandler) error {
	if handler == nil {
		return fmt.Errorf("event handler cannot be nil")
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	if bus.subscribers[eventType] == nil {
		bus.subscribers[eventType] = make([]*eventSubscription, 0)
	}

	subscription := &eventSubscription{
		handler: handler,
		active:  true,
	}

	bus.subscribers[eventType] = append(bus.subscribers[eventType], subscription)

	// 按优先级排序
	bus.sortSubscribersByPriority(eventType)

	bus.logger.Info("Event handler subscribed",
		"event_type", eventType,
		"handler_id", handler.GetID(),
		"priority", handler.GetPriority(),
		"async", handler.IsAsync())

	return nil
}

// Unsubscribe 取消订阅
func (bus *DefaultEventBus) Unsubscribe(eventType EventType, handlerID string) error {
	bus.mu.Lock()
	defer bus.mu.Unlock()

	subscriptions, exists := bus.subscribers[eventType]
	if !exists {
		return fmt.Errorf("no subscribers for event type '%s'", eventType)
	}

	for i, subscription := range subscriptions {
		if subscription.handler.GetID() == handlerID {
			subscription.active = false
			bus.subscribers[eventType] = append(subscriptions[:i], subscriptions[i+1:]...)
			bus.logger.Info("Event handler unsubscribed",
				"event_type", eventType,
				"handler_id", handlerID)
			return nil
		}
	}

	return fmt.Errorf("handler '%s' not found for event type '%s'", handlerID, eventType)
}

// Publish 发布事件（同步）
func (bus *DefaultEventBus) Publish(event *Event) error {
	return bus.publishEvent(event, false)
}

// PublishAsync 发布事件（异步）
func (bus *DefaultEventBus) PublishAsync(event *Event) error {
	return bus.publishEvent(event, true)
}

// publishEvent 发布事件的内部实现
func (bus *DefaultEventBus) publishEvent(event *Event, async bool) error {
	if !bus.running {
		return fmt.Errorf("event bus is stopped")
	}

	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	bus.mu.RLock()
	subscriptions := bus.subscribers[event.Type]
	middleware := bus.middleware
	bus.mu.RUnlock()

	if len(subscriptions) == 0 {
		bus.logger.Debug("No subscribers for event", "event_type", event.Type)
		return nil
	}

	bus.logger.Debug("Publishing event",
		"event_type", event.Type,
		"event_id", event.ID,
		"async", async,
		"subscribers", len(subscriptions))

	startTime := time.Now()

	// 创建执行链
	chain := bus.createExecutionChain(event, subscriptions, middleware)

	// 执行事件处理
	if async {
		bus.wg.Add(1)
		go func() {
			defer bus.wg.Done()
			bus.executeChain(chain, event)
		}()
	} else {
		bus.executeChain(chain, event)
	}

	// 记录指标
	duration := time.Since(startTime)
	bus.metrics.RecordProcessingTime(event.Type, duration)

	return nil
}

// createExecutionChain 创建执行链
func (bus *DefaultEventBus) createExecutionChain(event *Event, subscriptions []*eventSubscription, middleware []EventMiddleware) []EventHandler {
	// 创建处理器链
	var handlers []EventHandler
	for _, subscription := range subscriptions {
		if subscription.active {
			handlers = append(handlers, subscription.handler)
		}
	}

	// 应用中间件
	if len(middleware) > 0 {
		// 按顺序排序中间件
		sort.Slice(middleware, func(i, j int) bool {
			return middleware[i].GetOrder() < middleware[j].GetOrder()
		})

		// 创建中间件链
		var chain []EventHandler
		for i := len(handlers) - 1; i >= 0; i-- {
			handler := handlers[i]
			for _, mw := range middleware {
				currentHandler := handler
				wrappedHandler := &MiddlewareWrapper{
					middleware: mw,
					next:       currentHandler,
				}
				handler = wrappedHandler
			}
			chain = append([]EventHandler{handler}, chain...)
		}
		return chain
	}

	return handlers
}

// executeChain 执行处理器链
func (bus *DefaultEventBus) executeChain(handlers []EventHandler, event *Event) {
	for _, handler := range handlers {
		if !bus.running {
			break
		}

		startTime := time.Now()
		err := handler.Handle(event)
		duration := time.Since(startTime)

		if err != nil {
			bus.metrics.RecordError(event.Type, err)
			bus.logger.Error("Event handler error",
				"event_type", event.Type,
				"event_id", event.ID,
				"handler_id", handler.GetID(),
				"error", err,
				"duration", duration)
		} else {
			bus.logger.Debug("Event handler executed",
				"event_type", event.Type,
				"event_id", event.ID,
				"handler_id", handler.GetID(),
				"duration", duration,
				"async", handler.IsAsync())
		}
	}
}

// sortSubscribersByPriority 按优先级排序订阅者
func (bus *DefaultEventBus) sortSubscribersByPriority(eventType EventType) {
	subscriptions := bus.subscribers[eventType]
	sort.Slice(subscriptions, func(i, j int) bool {
		return subscriptions[i].handler.GetPriority() > subscriptions[j].handler.GetPriority()
	})
}

// PublishBatch 批量发布事件
func (bus *DefaultEventBus) PublishBatch(events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	bus.wg.Add(1)
	go func() {
		defer bus.wg.Done()
		for _, event := range events {
			if !bus.running {
				break
			}
			bus.PublishAsync(event)
		}
	}()

	return nil
}

// AddMiddleware 添加中间件
func (bus *DefaultEventBus) AddMiddleware(middleware EventMiddleware) error {
	if middleware == nil {
		return fmt.Errorf("middleware cannot be nil")
	}

	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.middleware = append(bus.middleware, middleware)

	bus.logger.Info("Event middleware added",
		"middleware_order", middleware.GetOrder())

	return nil
}

// RemoveMiddleware 移除中间件
func (bus *DefaultEventBus) RemoveMiddleware(middlewareID string) error {
	bus.mu.Lock()
	defer bus.mu.Unlock()

	for i, mw := range bus.middleware {
		// 这里需要中间件接口提供ID方法，或者使用其他方式识别
		// 简化实现，假设中间件有唯一标识
		if fmt.Sprintf("%p", mw) == middlewareID {
			bus.middleware = append(bus.middleware[:i], bus.middleware[i+1:]...)
			bus.logger.Info("Event middleware removed", "middleware_id", middlewareID)
			return nil
		}
	}

	return fmt.Errorf("middleware '%s' not found", middlewareID)
}

// GetSubscriberCount 获取订阅者数量
func (bus *DefaultEventBus) GetSubscriberCount(eventType EventType) int {
	bus.mu.RLock()
	defer bus.mu.RUnlock()

	count := 0
	for _, subscription := range bus.subscribers[eventType] {
		if subscription.active {
			count++
		}
	}

	return count
}

// GetEventTypes 获取所有事件类型
func (bus *DefaultEventBus) GetEventTypes() []EventType {
	bus.mu.RLock()
	defer bus.mu.RUnlock()

	types := make([]EventType, 0, len(bus.subscribers))
	for eventType := range bus.subscribers {
		types = append(types, eventType)
	}

	return types
}

// Clear 清空所有订阅
func (bus *DefaultEventBus) Clear() {
	bus.mu.Lock()
	defer bus.mu.Unlock()

	bus.subscribers = make(map[EventType][]*eventSubscription)
	bus.middleware = make([]EventMiddleware, 0)

	bus.logger.Info("All event subscriptions cleared")
}

// Stop 停止事件总线
func (bus *DefaultEventBus) Stop() error {
	if !bus.running {
		return nil
	}

	bus.logger.Info("Stopping event bus")
	bus.running = false
	bus.cancel()

	// 等待所有异步处理完成
	bus.wg.Wait()

	bus.logger.Info("Event bus stopped")
	return nil
}

// GetMetrics 获取事件指标
func (bus *DefaultEventBus) GetMetrics() EventMetrics {
	return bus.metrics
}

// MiddlewareWrapper 中间件包装器
type MiddlewareWrapper struct {
	middleware EventMiddleware
	next       EventHandler
}

// Handle 处理事件
func (mw *MiddlewareWrapper) Handle(event *Event) error {
	return mw.middleware.Process(event, mw.next)
}

func (mw *MiddlewareWrapper) GetID() string {
	return fmt.Sprintf("middleware_wrapper_%p", mw.middleware)
}

func (mw *MiddlewareWrapper) GetPriority() int {
	return mw.next.GetPriority()
}

func (mw *MiddlewareWrapper) IsAsync() bool {
	return mw.next.IsAsync()
}

// DefaultEventMetrics 默认事件指标实现
type DefaultEventMetrics struct {
	stats map[EventType]*EventStats
	mu    sync.RWMutex
}

// NewDefaultEventMetrics 创建默认事件指标
func NewDefaultEventMetrics() *DefaultEventMetrics {
	return &DefaultEventMetrics{
		stats: make(map[EventType]*EventStats),
	}
}

// RecordProcessingTime 记录事件处理时间
func (m *DefaultEventMetrics) RecordProcessingTime(eventType EventType, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, exists := m.stats[eventType]
	if !exists {
		stats = &EventStats{
			EventType:        eventType,
			MinProcessingTime: duration,
			MaxProcessingTime: duration,
		}
		m.stats[eventType] = stats
	}

	stats.TotalEvents++
	stats.SuccessEvents++
	stats.LastProcessed = time.Now()

	// 更新平均处理时间
	if stats.TotalEvents == 1 {
		stats.AvgProcessingTime = duration
	} else {
		totalTime := stats.AvgProcessingTime * time.Duration(stats.TotalEvents-1)
		stats.AvgProcessingTime = (totalTime + duration) / time.Duration(stats.TotalEvents)
	}

	// 更新最大最小处理时间
	if duration > stats.MaxProcessingTime {
		stats.MaxProcessingTime = duration
	}
	if duration < stats.MinProcessingTime {
		stats.MinProcessingTime = duration
	}
}

// RecordError 记录事件处理错误
func (m *DefaultEventMetrics) RecordError(eventType EventType, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, exists := m.stats[eventType]
	if !exists {
		stats = &EventStats{
			EventType: eventType,
		}
		m.stats[eventType] = stats
	}

	stats.TotalEvents++
	stats.ErrorEvents++
	stats.LastProcessed = time.Now()
}

// GetStats 获取事件处理统计
func (m *DefaultEventMetrics) GetStats(eventType EventType) *EventStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats, exists := m.stats[eventType]
	if !exists {
		return &EventStats{EventType: eventType}
	}

	// 返回副本
	copy := *stats
	return &copy
}

// GetAllStats 获取所有事件统计
func (m *DefaultEventMetrics) GetAllStats() map[EventType]*EventStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[EventType]*EventStats)
	for k, v := range m.stats {
		copy := *v
		result[k] = &copy
	}

	return result
}

// Reset 重置统计
func (m *DefaultEventMetrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats = make(map[EventType]*EventStats)
}

// LoggingMiddleware 日志中间件
type LoggingMiddleware struct {
	logger logger.Logger
	order  int
}

// NewLoggingMiddleware 创建日志中间件
func NewLoggingMiddleware(logger logger.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{
		logger: logger,
		order:  0,
	}
}

// Process 处理事件
func (m *LoggingMiddleware) Process(event *Event, next EventHandler) error {
	startTime := time.Now()
	m.logger.Debug("Processing event",
		"event_type", event.Type,
		"event_id", event.ID,
		"handler_id", next.GetID())

	err := next.Handle(event)
	duration := time.Since(startTime)

	m.logger.Debug("Event processed",
		"event_type", event.Type,
		"event_id", event.ID,
		"handler_id", next.GetID(),
		"duration", duration,
		"error", err)

	return err
}

// GetOrder 获取执行顺序
func (m *LoggingMiddleware) GetOrder() int {
	return m.order
}

// SetOrder 设置执行顺序
func (m *LoggingMiddleware) SetOrder(order int) {
	m.order = order
}

// MetricsMiddleware 指标收集中间件
type MetricsMiddleware struct {
	metrics EventMetrics
	order   int
}

// NewMetricsMiddleware 创建指标收集中间件
func NewMetricsMiddleware(metrics EventMetrics) *MetricsMiddleware {
	return &MetricsMiddleware{
		metrics: metrics,
		order:   10,
	}
}

// Process 处理事件
func (m *MetricsMiddleware) Process(event *Event, next EventHandler) error {
	startTime := time.Now()
	err := next.Handle(event)
	duration := time.Since(startTime)

	if err != nil {
		m.metrics.RecordError(event.Type, err)
	} else {
		m.metrics.RecordProcessingTime(event.Type, duration)
	}

	return err
}

// GetOrder 获取执行顺序
func (m *MetricsMiddleware) GetOrder() int {
	return m.order
}

// SetOrder 设置执行顺序
func (m *MetricsMiddleware) SetOrder(order int) {
	m.order = order
}