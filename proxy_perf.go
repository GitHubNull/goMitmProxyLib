package main

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mintux/goMitmProxyLib/src"
	"github.com/mintux/goMitmProxyLib/src/types"
)

// ProxyPerformanceTest 代理性能测试
func ProxyPerformanceTest() {
	// 创建测试目标服务器
	targetServer := &http.Server{
		Addr: ":9999",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"message": "success", "timestamp": "` + time.Now().Format(time.RFC3339) + `"}`))
		}),
	}

	go targetServer.ListenAndServe()
	defer targetServer.Close()

	// 等待目标服务器启动
	time.Sleep(2 * time.Second)

	// 创建代理服务器配置
	config := &types.Config{
		ListenAddr:        ":8080",
		EnableHTTPS:       true,
		MaxIdleConns:      100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:   90 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		LogLevel:          "info",
		LogFormat:         "json",
	}

	// 创建并启动代理服务器
	proxy, err := src.NewMitmProxy(config)
	if err != nil {
		fmt.Printf("Failed to create proxy: %v\n", err)
		return
	}

	// 启动代理服务器
	if err := proxy.Start(); err != nil {
		fmt.Printf("Failed to start proxy: %v\n", err)
		return
	}

	// 等待代理服务器启动
	time.Sleep(2 * time.Second)

	fmt.Printf("代理性能测试开始:\n")
	fmt.Printf("代理服务器地址: %s\n", config.ListenAddr)
	fmt.Printf("目标服务器地址: %s\n", targetServer.Addr)

	// 测试参数
	const (
		totalRequests = 1000
		numWorkers   = 10
		requestsPerWorker = totalRequests / numWorkers
	)

	// 创建HTTP客户端（通过代理）
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("http://localhost:8080")
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("工作线程数: %d\n", numWorkers)
	fmt.Printf("每线程请求数: %d\n", requestsPerWorker)

	// 统计变量
	var (
		successRequests   int64
		failedRequests    int64
		totalDuration     int64
		startTime        = time.Now()
	)

	// 工作协程
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := 0; j < requestsPerWorker; j++ {
				reqStart := time.Now()

				// 发送请求通过代理
				resp, err := client.Get("http://localhost:9999/test")
				duration := time.Since(reqStart)

				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
					fmt.Printf("Worker %d, Request %d: %v\n", workerID, j, err)
				} else if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successRequests, 1)
					resp.Body.Close()
				}

				atomic.AddInt64(&totalDuration, duration.Nanoseconds())
			}
		}(i)
	}

	// 等待所有请求完成
	wg.Wait()

	endTime := time.Now()
	totalTime := endTime.Sub(startTime)

	// 计算性能指标
	successRate := float64(successRequests) / float64(totalRequests) * 100
	avgDuration := time.Duration(totalDuration) / time.Duration(totalRequests)
	rps := float64(totalRequests) / totalTime.Seconds()

	fmt.Printf("\n=== 代理性能测试结果 ===\n")
	fmt.Printf("总请求数:       %d\n", totalRequests)
	fmt.Printf("成功请求数:       %d\n", successRequests)
	fmt.Printf("失败请求数:       %d\n", failedRequests)
	fmt.Printf("成功率:             %.2f%%\n", successRate)
	fmt.Printf("平均响应时间:       %v\n", avgDuration)
	fmt.Printf("总耗时:             %v\n", totalTime)
	fmt.Printf("实际RPS:             %.2f requests/sec\n", rps)
	fmt.Printf("目标RPS:             300 requests/sec\n")
	fmt.Printf("RPS达标:             %v\n", rps >= 300)

	// 获取代理统计信息
	stats := proxy.GetStats()
	fmt.Printf("\n=== 代理服务器统计 ===\n")
	if proxyStats, ok := stats["proxy"]; ok {
		fmt.Printf("代理统计: %+v\n", proxyStats)
	}

	// 停止代理服务器
	if err := proxy.Stop(); err != nil {
		fmt.Printf("Failed to stop proxy: %v\n", err)
	}
}

func main() {
	fmt.Println("=== GoMitmProxyLib 代理性能测试 ===")
	fmt.Println()

	ProxyPerformanceTest()
}