package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLogConfig(t *testing.T) {
	config := DefaultLogConfig()

	assert.NotNil(t, config)
	assert.Equal(t, LogLevelInfo, config.Level)
	assert.Equal(t, LogFormatJSON, config.Format)
	assert.Equal(t, "stdout", config.Output)
	assert.Equal(t, 100, config.MaxSize)
	assert.Equal(t, 30, config.MaxAge)
	assert.Equal(t, 10, config.MaxBackups)
	assert.True(t, config.Compress)
	assert.True(t, config.Console)
	assert.True(t, config.Caller)
	assert.NotNil(t, config.Fields)
}

func TestNewLogger(t *testing.T) {
	config := &LogConfig{
		Level:    LogLevelDebug,
		Format:   LogFormatText,
		Output:   "stdout",
		Console:  false,
		Caller:   false,
		TimeFormat: "2006-01-02 15:04:05",
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)

	assert.Equal(t, LogLevelDebug, logger.GetLevel())
}

func TestNewLoggerWithNilConfig(t *testing.T) {
	logger, err := NewLogger(nil)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// 应该使用默认配置
	assert.Equal(t, LogLevelInfo, logger.GetLevel())
}

func TestLoggerLevels(t *testing.T) {
	config := &LogConfig{
		Level:    LogLevelDebug,
		Format:   LogFormatText,
		Output:   "stdout",
		Console:  false,
		Caller:   false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 测试所有日志级别
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	// 测试格式化方法
	logger.Debugf("debug %s", "message")
	logger.Infof("info %s", "message")
	logger.Warnf("warn %s", "message")
	logger.Errorf("error %s", "message")
}

func TestLoggerWithFields(t *testing.T) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatJSON,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 测试单个字段
	logger1 := logger.With("key1", "value1")
	assert.NotNil(t, logger1)

	// 测试多个字段
	logger2 := logger.WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	})
	assert.NotNil(t, logger2)

	logger2.Info("test message")
}

func TestLoggerSetLevel(t *testing.T) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 测试设置不同级别
	logger.SetLevel(LogLevelDebug)
	assert.Equal(t, LogLevelDebug, logger.GetLevel())

	logger.SetLevel(LogLevelWarn)
	assert.Equal(t, LogLevelWarn, logger.GetLevel())

	logger.SetLevel(LogLevelError)
	assert.Equal(t, LogLevelError, logger.GetLevel())
}

func TestLoggerSync(t *testing.T) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 测试同步
	err = logger.Sync()
	assert.NoError(t, err)
}

func TestLoggerWithFileOutput(t *testing.T) {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "test_log_*.log")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	config := &LogConfig{
		Level:    LogLevelDebug,
		Format:   LogFormatJSON,
		Output:   tmpFile.Name(),
		Console:  false,
		Caller:   false,
		Filename: tmpFile.Name(),
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 写入日志
	logger.Info("test message")

	// 同步确保写入
	err = logger.Sync()
	require.NoError(t, err)

	// 读取文件内容
	data, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	// 验证JSON格式
	var logEntry map[string]interface{}
	err = json.Unmarshal(data, &logEntry)
	require.NoError(t, err)
	assert.Equal(t, "test message", logEntry["message"])
	assert.Equal(t, "info", logEntry["level"])
}

func TestLoggerWithConsoleOutput(t *testing.T) {
	config := &LogConfig{
		Level:    LogLevelInfo,
		Format:   LogFormatText,
		Output:   "stdout",
		Console:  true,
		Caller:   false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	// 测试控制台输出
	logger.Info("test console message")
}

func TestGlobalLogger(t *testing.T) {
	// 初始化全局日志
	config := &LogConfig{
		Level:   LogLevelDebug,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	err := InitGlobalLogger(config)
	require.NoError(t, err)

	// 获取全局日志
	logger := GetGlobalLogger()
	require.NotNil(t, logger)

	// 测试便捷函数
	Debug("debug message")
	Info("info message")
	Warn("warn message")
	Error("error message")

	Debugf("debug %s", "message")
	Infof("info %s", "message")
	Warnf("warn %s", "message")
	Errorf("error %s", "message")
}

func TestGetGlobalLoggerWithoutInit(t *testing.T) {
	// 重置全局日志
	GlobalLogger = nil

	// 获取全局日志（应该创建默认的）
	logger := GetGlobalLogger()
	require.NotNil(t, logger)
	assert.Equal(t, LogLevelInfo, logger.GetLevel())
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelDebug, "debug"},
		{LogLevelInfo, "info"},
		{LogLevelWarn, "warn"},
		{LogLevelError, "error"},
		{LogLevelFatal, "fatal"},
		{LogLevelPanic, "panic"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			config := &LogConfig{
				Level:   tt.level,
				Format:  LogFormatText,
				Output:  "stdout",
				Console: false,
				Caller:  false,
			}

			logger, err := NewLogger(config)
			require.NoError(t, err)
			assert.Equal(t, tt.level, logger.GetLevel())
		})
	}
}

func TestLogFormats(t *testing.T) {
	// 创建缓冲区捕获输出
	var buf bytes.Buffer

	// 测试JSON格式
	jsonConfig := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatJSON,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	jsonLogger, err := NewLogger(jsonConfig)
	require.NoError(t, err)
	jsonLogger.Info("json test message")

	// 测试文本格式
	textConfig := &LogConfig{
		Level:     LogLevelInfo,
		Format:    LogFormatText,
		Output:    "stdout",
		Console:   false,
		Caller:    false,
		TimeFormat: "2006-01-02 15:04:05",
	}

	textLogger, err := NewLogger(textConfig)
	require.NoError(t, err)
	textLogger.Info("text test message")
}

func TestLogTimeFormats(t *testing.T) {
	timeFormats := []string{
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, timeFormat := range timeFormats {
		t.Run(timeFormat, func(t *testing.T) {
			config := &LogConfig{
				Level:     LogLevelInfo,
				Format:    LogFormatText,
				Output:    "stdout",
				Console:   false,
				Caller:    false,
				TimeFormat: timeFormat,
			}

			logger, err := NewLogger(config)
			require.NoError(t, err)
			logger.Info("test message")
		})
	}
}

func TestLogFields(t *testing.T) {
	config := &LogConfig{
		Level:  LogLevelInfo,
		Format: LogFormatJSON,
		Output: "stdout",
		Fields: map[string]interface{}{
			"service": "test-service",
			"version": "1.0.0",
		},
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	logger.Info("test message with fields")

	// 测试带字段的日志
	logger.With("request_id", "12345").Info("request processed")
	logger.WithFields(map[string]interface{}{
		"user_id":    "user123",
		"action":     "login",
		"success":    true,
		"duration":   time.Millisecond * 150,
	}).Info("user action completed")
}

func TestLoggerWithCaller(t *testing.T) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  true,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	logger.Info("message with caller")
}

func TestLoggerWithoutCaller(t *testing.T) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(t, err)

	logger.Info("message without caller")
}

func BenchmarkLoggerInfo(b *testing.B) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message")
	}
}

func BenchmarkLoggerWithFields(b *testing.B) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(b, err)

	logger1 := logger.With("request_id", "12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger1.Info("benchmark message with fields")
	}
}

func BenchmarkLoggerJSONFormat(b *testing.B) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatJSON,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark json message")
	}
}

func BenchmarkLoggerTextFormat(b *testing.B) {
	config := &LogConfig{
		Level:   LogLevelInfo,
		Format:  LogFormatText,
		Output:  "stdout",
		Console: false,
		Caller:  false,
	}

	logger, err := NewLogger(config)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark text message")
	}
}