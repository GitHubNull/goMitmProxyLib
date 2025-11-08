package tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mintux/goMitmProxyLib/src"
	"github.com/mintux/goMitmProxyLib/src/hooks"
	"github.com/mintux/goMitmProxyLib/src/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyPerformance 测试代理性能
func TestProxyPerformance(t *testing.T) {
	// 创建测试目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "Hello from target server"}`))
	}))
	defer targetServer.Close()

	// 解析目标服务器URL
	targetURL, err := url.Parse(targetServer.URL)
	require.NoError(t, err)

	// 创建代理配置
	config := &types.Config{
		ListenAddr:          "127.0.0.1:0", // 使用随机端口
		EnableHTTPS:         false,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		LogLevel:            "error", // 减少日志输出以提高性能
		LogFormat:           "json",
		LogOutput:           "stdout",
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	require.NoError(t, err)

	// 启动代理
	err = proxy.Start()
	require.NoError(t, err)
	defer proxy.Stop()

	// 获取代理地址
	proxyAddr := proxy.GetProxyServer().GetAddr()

	// 性能测试参数
	const (
		numRequests   = 1000
		numWorkers    = 50
		targetRPS     = 300 // 目标每秒请求数
		batchSize     = 10
		requestDelay  = time.Duration(numWorkers*1000/targetRPS) * time.Millisecond
	)

	// 统计变量
	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
		totalDuration   int64
		errorCount      int64
	)

	// 创建测试客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// 创建测试上下文
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 启动性能监控
	var wg sync.WaitGroup
	performanceCtx, performanceCancel := context.WithCancel(context.Background())
	defer performanceCancel()

	// 性能监控goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				stats := proxy.GetStats()
				t.Logf("Stats - Total: %d, Active: %d, Errors: %d, Bytes: %d/%d",
					stats["proxy"].(*types.ProxyStats).TotalRequests,
					stats["proxy"].(*types.ProxyStats).ActiveConnections,
					stats["proxy"].(*types.ProxyStats).Errors,
					stats["proxy"].(*types.ProxyStats).BytesReceived,
					stats["proxy"].(*types.ProxyStats).BytesSent)
			case <-performanceCtx.Done():
				return
			}
		}
	}()

	// 启动工作goroutine
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				default:
					// 检查是否达到请求数量
					if atomic.LoadInt64(&totalRequests) >= numRequests {
						return
					}

					// 限制请求速率
					time.Sleep(requestDelay)

					// 执行请求
					startTime := time.Now()

					// 构造代理URL
					proxyURL := fmt.Sprintf("http://%s%s", proxyAddr, targetURL.Path)

					req, err := http.NewRequestWithContext(ctx, "GET", proxyURL, nil)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
						continue
					}

					// 设置目标主机头
					req.Header.Set("Host", targetURL.Host)

					resp, err := client.Do(req)
					duration := time.Since(startTime)

					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						atomic.AddInt64(&errorCount, 1)
						t.Logf("Worker %d: Request failed: %v", workerID, err)
						continue
					}

					// 读取响应
					body, err := io.ReadAll(resp.Body)
					resp.Body.Close()

					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						atomic.AddInt64(&errorCount, 1)
						t.Logf("Worker %d: Failed to read response: %v", workerID, err)
						continue
					}

					// 验证响应
					if resp.StatusCode == http.StatusOK && len(body) > 0 {
						atomic.AddInt64(&successRequests, 1)
					} else {
						atomic.AddInt64(&failedRequests, 1)
						t.Logf("Worker %d: Unexpected response: %d, %d bytes", workerID, resp.StatusCode, len(body))
					}

					atomic.AddInt64(&totalRequests, 1)
					atomic.AddInt64(&totalDuration, duration.Nanoseconds())

					// 批量处理延迟
					if atomic.LoadInt64(&totalRequests)%batchSize == 0 {
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
		}(i)
	}

	// 等待所有请求完成
	wg.Wait()

	// 停止性能监控
	performanceCancel()

	// 计算性能指标
	total := atomic.LoadInt64(&totalRequests)
	success := atomic.LoadInt64(&successRequests)
	failed := atomic.LoadInt64(&failedRequests)
	errors := atomic.LoadInt64(&errorCount)
	durationSum := atomic.LoadInt64(&totalDuration)

	successRate := float64(success) / float64(total) * 100
	avgDuration := time.Duration(durationSum / total)
	actualRPS := float64(total) / time.Since(time.Now().Add(-time.Since(time.Now()))).Seconds()

	// 获取最终统计信息
	finalStats := proxy.GetStats()
	proxyStats := finalStats["proxy"].(*types.ProxyStats)

	// 输出性能报告
	t.Logf("=== Performance Test Results ===")
	t.Logf("Total Requests:     %d", total)
	t.Logf("Success Requests:   %d (%.2f%%)", success, successRate)
	t.Logf("Failed Requests:    %d", failed)
	t.Logf("Error Count:        %d", errors)
	t.Logf("Average Duration:   %v", avgDuration)
	t.Logf("Actual RPS:         %.2f", actualRPS)
	t.Logf("Target RPS:         %d", targetRPS)
	t.Logf("Proxy Stats:")
	t.Logf("  Total Requests:   %d", proxyStats.TotalRequests)
	t.Logf("  Active Connections: %d", proxyStats.ActiveConnections)
	t.Logf("  Bytes Received:   %d", proxyStats.BytesReceived)
	t.Logf("  Bytes Sent:       %d", proxyStats.BytesSent)
	t.Logf("  Errors:           %d", proxyStats.Errors)
	t.Logf("System Info:")
	t.Logf("  Goroutines:       %d", runtime.NumGoroutine())
	t.Logf("  CPU Count:        %d", runtime.NumCPU())

	// 性能断言
	assert.Equal(t, int64(numRequests), total, "Total requests should match expected")
	assert.GreaterOrEqual(t, successRate, 95.0, "Success rate should be at least 95%")
	assert.GreaterOrEqual(t, actualRPS, float64(targetRPS)*0.8, "Actual RPS should be at least 80% of target")
	assert.Less(t, avgDuration, 1*time.Second, "Average duration should be less than 1 second")
}

// BenchmarkProxyRequest 代理请求基准测试
func BenchmarkProxyRequest(b *testing.B) {
	// 创建测试目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message": "benchmark response"}`))
	}))
	defer targetServer.Close()

	// 创建代理配置
	config := &types.Config{
		ListenAddr:          "127.0.0.1:0",
		EnableHTTPS:         false,
		ReadTimeout:         10 * time.Second,
		WriteTimeout:        10 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		LogLevel:            "error",
		LogFormat:           "json",
		LogOutput:           "stdout",
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	require.NoError(b, err)

	// 启动代理
	err = proxy.Start()
	require.NoError(b, err)
	defer proxy.Stop()

	// 获取代理地址
	proxyAddr := proxy.GetProxyServer().GetAddr()

	// 创建测试客户端
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// 准备请求
	targetURL, _ := url.Parse(targetServer.URL)
	proxyURL := fmt.Sprintf("http://%s%s", proxyAddr, targetURL.Path)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, err := http.NewRequest("GET", proxyURL, nil)
			if err != nil {
				b.Error(err)
				continue
			}

			req.Header.Set("Host", targetURL.Host)

			resp, err := client.Do(req)
			if err != nil {
				b.Error(err)
				continue
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// TestConcurrentConnections 并发连接测试
func TestConcurrentConnections(t *testing.T) {
	// 创建测试目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟一些处理时间
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	// 创建代理配置
	config := &types.Config{
		ListenAddr:          "127.0.0.1:0",
		EnableHTTPS:         false,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		LogLevel:            "error",
		LogFormat:           "json",
		LogOutput:           "stdout",
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	require.NoError(t, err)

	// 启动代理
	err = proxy.Start()
	require.NoError(t, err)
	defer proxy.Stop()

	// 获取代理地址
	proxyAddr := proxy.GetProxyServer().GetAddr()

	// 并发测试参数
	const (
		numWorkers    = 100
		requestsPerWorker = 50
	)

	var wg sync.WaitGroup
	var (
		totalRequests   int64
		successRequests int64
		failedRequests  int64
	)

	// 创建测试客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// 启动并发工作goroutine
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			targetURL, _ := url.Parse(targetServer.URL)
			proxyURL := fmt.Sprintf("http://%s%s", proxyAddr, targetURL.Path)

			for j := 0; j < requestsPerWorker; j++ {
				req, err := http.NewRequest("GET", proxyURL, nil)
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
					continue
				}

				req.Header.Set("Host", targetURL.Host)

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
					continue
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successRequests, 1)
				} else {
					atomic.AddInt64(&failedRequests, 1)
				}

				atomic.AddInt64(&totalRequests, 1)
			}
		}(i)
	}

	// 等待所有请求完成
	wg.Wait()

	// 计算结果
	total := atomic.LoadInt64(&totalRequests)
	success := atomic.LoadInt64(&successRequests)
	failed := atomic.LoadInt64(&failedRequests)
	successRate := float64(success) / float64(total) * 100

	expectedTotal := int64(numWorkers * requestsPerWorker)

	t.Logf("Concurrent Connection Test Results:")
	t.Logf("Expected Total:     %d", expectedTotal)
	t.Logf("Actual Total:       %d", total)
	t.Logf("Success Requests:   %d (%.2f%%)", success, successRate)
	t.Logf("Failed Requests:    %d", failed)
	t.Logf("Success Rate:       %.2f%%", successRate)

	// 断言
	assert.Equal(t, expectedTotal, total, "Total requests should match expected")
	assert.GreaterOrEqual(t, successRate, 95.0, "Success rate should be at least 95%")
}

// TestMemoryUsage 内存使用测试
func TestMemoryUsage(t *testing.T) {
	// 创建代理配置
	config := &types.Config{
		ListenAddr:          "127.0.0.1:0",
		EnableHTTPS:         false,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		LogLevel:            "error",
		LogFormat:           "json",
		LogOutput:           "stdout",
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	require.NoError(t, err)

	// 启动代理
	err = proxy.Start()
	require.NoError(t, err)
	defer proxy.Stop()

	// 记录初始内存使用
	var initialMem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&initialMem)

	// 创建测试目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Memory test response"))
	}))
	defer targetServer.Close()

	// 获取代理地址
	proxyAddr := proxy.GetProxyServer().GetAddr()

	// 创建测试客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 执行大量请求
	const numRequests = 5000
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			targetURL, _ := url.Parse(targetServer.URL)
			proxyURL := fmt.Sprintf("http://%s%s", proxyAddr, targetURL.Path)

			for j := 0; j < numRequests/10; j++ {
				req, _ := http.NewRequest("GET", proxyURL, nil)
				req.Header.Set("Host", targetURL.Host)

				resp, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}

	wg.Wait()

	// 记录最终内存使用
	var finalMem runtime.MemStats
	runtime.GC()
	runtime.GC() // 强制两次GC
	runtime.ReadMemStats(&finalMem)

	// 计算内存增长
	memIncrease := finalMem.Alloc - initialMem.Alloc
	memIncreaseMB := float64(memIncrease) / 1024 / 1024

	t.Logf("Memory Usage Test Results:")
	t.Logf("Initial Memory:    %.2f MB", float64(initialMem.Alloc)/1024/1024)
	t.Logf("Final Memory:      %.2f MB", float64(finalMem.Alloc)/1024/1024)
	t.Logf("Memory Increase:  %.2f MB", memIncreaseMB)
	t.Logf("Total Requests:    %d", numRequests)
	t.Logf("Memory per Request: %.2f KB", memIncreaseMB*1024/float64(numRequests))

	// 内存使用不应该过度增长
	assert.Less(t, memIncreaseMB, 100.0, "Memory increase should be less than 100 MB")
}

// TestHookPerformance 钩子性能测试
func TestHookPerformance(t *testing.T) {
	// 创建代理配置
	config := &types.Config{
		ListenAddr:          "127.0.0.1:0",
		EnableHTTPS:         false,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		LogLevel:            "error",
		LogFormat:           "json",
		LogOutput:           "stdout",
	}

	// 创建代理实例
	proxy, err := src.NewMitmProxy(config)
	require.NoError(t, err)

	// 注册多个钩子
	hookManager := proxy.GetHookManager()
	for i := 0; i < 10; i++ {
		hookName := fmt.Sprintf("perf_hook_%d", i)
		hookFunc := func(ctx *types.ProxyContext) *types.HookResult {
			// 模拟一些轻量级处理
			ctx.Metadata["hook_processed"] = true
			return &types.HookResult{Action: types.ActionContinue}
		}

		metadata := &hooks.HookMetadata{
			Name:        hookName,
			Description: "Performance test hook",
			Priority:    100 + i,
			Version:     "1.0.0",
			Author:      "test",
		}

		err := hookManager.Register(hooks.HookOnRequestReceived, hookFunc, metadata)
		require.NoError(t, err)
	}

	// 启动代理
	err = proxy.Start()
	require.NoError(t, err)
	defer proxy.Stop()

	// 创建测试目标服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hook performance test"))
	}))
	defer targetServer.Close()

	// 性能测试
	const numRequests = 1000
	startTime := time.Now()

	// 创建测试客户端
	client := &http.Client{Timeout: 10 * time.Second}
	proxyAddr := proxy.GetProxyServer().GetAddr()
	targetURL, _ := url.Parse(targetServer.URL)
	proxyURL := fmt.Sprintf("http://%s%s", proxyAddr, targetURL.Path)

	// 执行请求
	for i := 0; i < numRequests; i++ {
		req, _ := http.NewRequest("GET", proxyURL, nil)
		req.Header.Set("Host", targetURL.Host)

		resp, err := client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	duration := time.Since(startTime)
	rps := float64(numRequests) / duration.Seconds()
	avgDuration := duration / time.Duration(numRequests)

	t.Logf("Hook Performance Test Results:")
	t.Logf("Total Requests:    %d", numRequests)
	t.Logf("Total Duration:    %v", duration)
	t.Logf("RPS:               %.2f", rps)
	t.Logf("Avg Duration:      %v", avgDuration)
	t.Logf("Hooks per Request: 10")

	// 性能断言
	assert.Greater(t, rps, 200.0, "RPS should be greater than 200 with hooks")
	assert.Less(t, avgDuration, 100*time.Millisecond, "Average duration should be less than 100ms")
}