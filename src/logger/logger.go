package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

// LogFormat 日志格式
type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

// LogConfig 日志配置
type LogConfig struct {
	Level       LogLevel   `json:"level" yaml:"level"`
	Format      LogFormat  `json:"format" yaml:"format"`
	Output      string     `json:"output" yaml:"output"`
	Filename    string     `json:"filename" yaml:"filename"`
	MaxSize     int        `json:"max_size" yaml:"max_size"`         // MB
	MaxAge      int        `json:"max_age" yaml:"max_age"`           // days
	MaxBackups  int        `json:"max_backups" yaml:"max_backups"`   // files
	Compress    bool       `json:"compress" yaml:"compress"`
	Console     bool       `json:"console" yaml:"console"`
	TimeFormat  string     `json:"time_format" yaml:"time_format"`
	Caller      bool       `json:"caller" yaml:"caller"`
	StackLevel  string     `json:"stack_level" yaml:"stack_level"`
	Fields      map[string]interface{} `json:"fields" yaml:"fields"`
}

// DefaultLogConfig 默认日志配置
func DefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      LogLevelInfo,
		Format:     LogFormatJSON,
		Output:     "stdout",
		Filename:   "",
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
		Compress:   true,
		Console:    true,
		TimeFormat: "2006-01-02 15:04:05.000",
		Caller:     true,
		StackLevel: "error",
		Fields:     make(map[string]interface{}),
	}
}

// Logger 日志接口
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	Panic(msg string, fields ...interface{})

	Debugf(template string, args ...interface{})
	Infof(template string, args ...interface{})
	Warnf(template string, args ...interface{})
	Errorf(template string, args ...interface{})
	Fatalf(template string, args ...interface{})
	Panicf(template string, args ...interface{})

	With(fields ...interface{}) Logger
	WithFields(fields map[string]interface{}) Logger

	// 获取底层zap logger
	GetZapLogger() *zap.Logger

	// 同步缓冲区
	Sync() error

	// 设置日志级别
	SetLevel(level LogLevel)

	// 获取日志级别
	GetLevel() LogLevel
}

// ProxyLogger 代理日志实现
type ProxyLogger struct {
	logger *zap.Logger
	config *LogConfig
	level  zap.AtomicLevel
}

// NewLogger 创建新的日志实例
func NewLogger(config *LogConfig) (Logger, error) {
	if config == nil {
		config = DefaultLogConfig()
	}

	// 解析日志级别
	zapLevel, err := parseLogLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// 创建原子级别
	atomicLevel := zap.NewAtomicLevelAt(zapLevel)

	// 创建编码器
	encoder := buildEncoder(config)

	// 创建写入器
	writer, err := buildWriter(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build writer: %w", err)
	}

	// 创建核心
	core := zapcore.NewCore(encoder, writer, atomicLevel)

	// 创建logger
	var logger *zap.Logger
	if config.Caller {
		logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(parseStackLevel(config.StackLevel)))
	} else {
		logger = zap.New(core)
	}

	// 添加默认字段
	if len(config.Fields) > 0 {
		fields := make([]zap.Field, 0, len(config.Fields))
		for k, v := range config.Fields {
			fields = append(fields, zap.Any(k, v))
		}
		logger = logger.With(fields...)
	}

	return &ProxyLogger{
		logger: logger,
		config: config,
		level:  atomicLevel,
	}, nil
}

// parseLogLevel 解析日志级别
func parseLogLevel(level LogLevel) (zapcore.Level, error) {
	switch strings.ToLower(string(level)) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

// parseStackLevel 解析堆栈级别
func parseStackLevel(level string) zapcore.LevelEnabler {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	case "panic":
		return zapcore.PanicLevel
	default:
		return zapcore.ErrorLevel
	}
}

// buildZapConfig 构建zap配置
func buildZapConfig(config *LogConfig, level zap.AtomicLevel) zap.Config {
	var zapConfig zap.Config
	if config.Format == LogFormatJSON {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}

	zapConfig.Level = level
	zapConfig.OutputPaths = []string{config.Output}
	if config.Filename != "" {
		zapConfig.OutputPaths = append(zapConfig.OutputPaths, config.Filename)
	}
	zapConfig.ErrorOutputPaths = zapConfig.OutputPaths
	zapConfig.DisableCaller = !config.Caller

	_ = zapConfig // 避免未使用警告
	return zapConfig
}

// buildEncoder 构建编码器
func buildEncoder(config *LogConfig) zapcore.Encoder {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     buildTimeEncoder(config.TimeFormat),
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if config.Format == LogFormatJSON {
		return zapcore.NewJSONEncoder(encoderConfig)
	}
	return zapcore.NewConsoleEncoder(encoderConfig)
}

// buildTimeEncoder 构建时间编码器
func buildTimeEncoder(format string) zapcore.TimeEncoder {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}

	return func(time time.Time, encoder zapcore.PrimitiveArrayEncoder) {
		encoder.AppendString(time.Format(format))
	}
}

// buildWriter 构建写入器
func buildWriter(config *LogConfig) (zapcore.WriteSyncer, error) {
	if config.Filename == "" {
		// 输出到控制台
		return zapcore.AddSync(os.Stdout), nil
	}

	// 确保目录存在
	dir := filepath.Dir(config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// 使用lumberjack进行日志轮转
	lumberjackLogger := &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxAge:     config.MaxAge,
		MaxBackups: config.MaxBackups,
		Compress:   config.Compress,
	}

	if config.Console {
		// 同时输出到控制台和文件
		return zapcore.AddSync(io.MultiWriter(os.Stdout, lumberjackLogger)), nil
	}

	return zapcore.AddSync(lumberjackLogger), nil
}

// Debug 输出调试日志
func (l *ProxyLogger) Debug(msg string, fields ...interface{}) {
	l.logger.Debug(msg, l.convertFields(fields...)...)
}

// Info 输出信息日志
func (l *ProxyLogger) Info(msg string, fields ...interface{}) {
	l.logger.Info(msg, l.convertFields(fields...)...)
}

// Warn 输出警告日志
func (l *ProxyLogger) Warn(msg string, fields ...interface{}) {
	l.logger.Warn(msg, l.convertFields(fields...)...)
}

// Error 输出错误日志
func (l *ProxyLogger) Error(msg string, fields ...interface{}) {
	l.logger.Error(msg, l.convertFields(fields...)...)
}

// Fatal 输出致命日志
func (l *ProxyLogger) Fatal(msg string, fields ...interface{}) {
	l.logger.Fatal(msg, l.convertFields(fields...)...)
}

// Panic 输出恐慌日志
func (l *ProxyLogger) Panic(msg string, fields ...interface{}) {
	l.logger.Panic(msg, l.convertFields(fields...)...)
}

// Debugf 格式化输出调试日志
func (l *ProxyLogger) Debugf(template string, args ...interface{}) {
	l.logger.Debug(fmt.Sprintf(template, args...))
}

// Infof 格式化输出信息日志
func (l *ProxyLogger) Infof(template string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(template, args...))
}

// Warnf 格式化输出警告日志
func (l *ProxyLogger) Warnf(template string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(template, args...))
}

// Errorf 格式化输出错误日志
func (l *ProxyLogger) Errorf(template string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(template, args...))
}

// Fatalf 格式化输出致命日志
func (l *ProxyLogger) Fatalf(template string, args ...interface{}) {
	l.logger.Fatal(fmt.Sprintf(template, args...))
}

// Panicf 格式化输出恐慌日志
func (l *ProxyLogger) Panicf(template string, args ...interface{}) {
	l.logger.Panic(fmt.Sprintf(template, args...))
}

// With 添加字段
func (l *ProxyLogger) With(fields ...interface{}) Logger {
	return &ProxyLogger{
		logger: l.logger.With(l.convertFields(fields...)...),
		config: l.config,
		level:  l.level,
	}
}

// WithFields 添加多个字段
func (l *ProxyLogger) WithFields(fields map[string]interface{}) Logger {
	zapFields := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		zapFields = append(zapFields, zap.Any(k, v))
	}

	return &ProxyLogger{
		logger: l.logger.With(zapFields...),
		config: l.config,
		level:  l.level,
	}
}

// GetZapLogger 获取底层zap logger
func (l *ProxyLogger) GetZapLogger() *zap.Logger {
	return l.logger
}

// Sync 同步缓冲区
func (l *ProxyLogger) Sync() error {
	return l.logger.Sync()
}

// SetLevel 设置日志级别
func (l *ProxyLogger) SetLevel(level LogLevel) {
	zapLevel, _ := parseLogLevel(level)
	l.level.SetLevel(zapLevel)
}

// GetLevel 获取日志级别
func (l *ProxyLogger) GetLevel() LogLevel {
	return LogLevel(l.level.Level().String())
}

// convertFields 转换字段格式
func (l *ProxyLogger) convertFields(fields ...interface{}) []zap.Field {
	if len(fields) == 0 {
		return nil
	}

	// 如果是map[string]interface{}格式
	if len(fields) == 1 {
		if m, ok := fields[0].(map[string]interface{}); ok {
			zapFields := make([]zap.Field, 0, len(m))
			for k, v := range m {
				zapFields = append(zapFields, zap.Any(k, v))
			}
			return zapFields
		}
	}

	// 如果是键值对格式
	if len(fields)%2 == 0 {
		zapFields := make([]zap.Field, 0, len(fields)/2)
		for i := 0; i < len(fields); i += 2 {
			if key, ok := fields[i].(string); ok {
				zapFields = append(zapFields, zap.Any(key, fields[i+1]))
			}
		}
		return zapFields
	}

	// 默认情况下，作为单个字段处理
	return []zap.Field{zap.Any("field", fields)}
}

// GetCaller 获取调用者信息
func GetCaller(skip int) (string, string, int) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "", "", 0
	}

	funcName := runtime.FuncForPC(pc).Name()
	filename := filepath.Base(file)

	return funcName, filename, line
}

// GlobalLogger 全局日志实例
var GlobalLogger Logger

// InitGlobalLogger 初始化全局日志
func InitGlobalLogger(config *LogConfig) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	GlobalLogger = logger
	return nil
}

// GetGlobalLogger 获取全局日志
func GetGlobalLogger() Logger {
	if GlobalLogger == nil {
		GlobalLogger, _ = NewLogger(DefaultLogConfig())
	}
	return GlobalLogger
}

// 便捷函数，使用全局日志实例
func Debug(msg string, fields ...interface{}) {
	GetGlobalLogger().Debug(msg, fields...)
}

func Info(msg string, fields ...interface{}) {
	GetGlobalLogger().Info(msg, fields...)
}

func Warn(msg string, fields ...interface{}) {
	GetGlobalLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...interface{}) {
	GetGlobalLogger().Error(msg, fields...)
}

func Fatal(msg string, fields ...interface{}) {
	GetGlobalLogger().Fatal(msg, fields...)
}

func Panic(msg string, fields ...interface{}) {
	GetGlobalLogger().Panic(msg, fields...)
}

func Debugf(template string, args ...interface{}) {
	GetGlobalLogger().Debugf(template, args...)
}

func Infof(template string, args ...interface{}) {
	GetGlobalLogger().Infof(template, args...)
}

func Warnf(template string, args ...interface{}) {
	GetGlobalLogger().Warnf(template, args...)
}

func Errorf(template string, args ...interface{}) {
	GetGlobalLogger().Errorf(template, args...)
}

func Fatalf(template string, args ...interface{}) {
	GetGlobalLogger().Fatalf(template, args...)
}

func Panicf(template string, args ...interface{}) {
	GetGlobalLogger().Panicf(template, args...)
}