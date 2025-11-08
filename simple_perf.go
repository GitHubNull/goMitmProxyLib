package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// SimplePerformanceTest 简单性能测试
func SimplePerformanceTest() {
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

	// 等待服务器启动
	time.Sleep(2 * time.Second)

	// 测试参数
	const (
		totalRequests = 1000
		numWorkers   = 10
		requestsPerWorker = totalRequests / numWorkers
	)

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	fmt.Printf("开始性能测试:\n")
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
				startTime := time.Now()

				// 发送请求
				resp, err := client.Get("http://localhost:9999/test")
				duration := time.Since(startTime)

				
				if err != nil {
					atomic.AddInt64(&failedRequests, 1)
					fmt.Printf("Worker %d, Request %d: %v\n", workerID, j, err)
				} else if resp.StatusCode == http.StatusOK {
					atomic.AddInt64(&successRequests, 1)
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

	fmt.Printf("\n=== 性能测试结果 ===\n")
	fmt.Printf("总请求数:       %d\n", totalRequests)
	fmt.Printf("成功请求数:       %d\n", successRequests)
	fmt.Printf("失败请求数:       %d\n", failedRequests)
	fmt.Printf("成功率:             %.2f%%\n", successRate)
	fmt.Printf("平均响应时间:       %v\n", avgDuration)
	fmt.Printf("总耗时:             %v\n", totalTime)
	fmt.Printf("实际RPS:             %.2f requests/sec\n", rps)
	fmt.Printf("目标RPS:             300 requests/sec\n")
	fmt.Printf("RPS达标:             %v\n", rps >= 300)

	// 清理
	targetServer.Close()
}

func main() {
	fmt.Println("=== GoMitmProxyLib 简单性能测试 ===")
	fmt.Println()

	SimplePerformanceTest()
}