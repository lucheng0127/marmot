package log

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

var levelNames = map[Level]string{
	DebugLevel: "DEBUG",
	InfoLevel:  "INFO",
	WarnLevel:  "WARN",
	ErrorLevel: "ERROR",
}

// Logger is a simple structured logger.
type Logger struct {
	mu     sync.Mutex
	level  Level
	format string // "text" or "json"
	out    io.Writer
}

var defaultLogger = New(InfoLevel, "text", os.Stdout)

// New creates a new Logger.
func New(level Level, format string, out io.Writer) *Logger {
	return &Logger{
		level:  level,
		format: format,
		out:    out,
	}
}

// FromLevel parses a level string (debug, info, warn, error).
func FromLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	default:
		return InfoLevel
	}
}

func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	switch l.format {
	case "json":
		l.writeJSON(level, msg, fields)
	default:
		l.writeText(level, msg, fields)
	}
}

func (l *Logger) writeJSON(level Level, msg string, fields map[string]interface{}) {
	// Minimal JSON output — will be extended later
	fmt.Fprintf(l.out, `{"time":"%s","level":"%s","msg":"%s"`,
		time.Now().Format(time.RFC3339),
		levelNames[level],
		msg,
	)
	for k, v := range fields {
		fmt.Fprintf(l.out, `,"%s":"%v"`, k, v)
	}
	fmt.Fprintln(l.out, "}")
}

func (l *Logger) writeText(level Level, msg string, fields map[string]interface{}) {
	ts := time.Now().Format("15:04:05.000")
	fmt.Fprintf(l.out, "%s [%s] %s", ts, levelNames[level], msg)
	for k, v := range fields {
		fmt.Fprintf(l.out, " %s=%v", k, v)
	}
	fmt.Fprintln(l.out)
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	l.log(DebugLevel, msg, mergeFields(fields...))
}

// Info logs at info level.
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	l.log(InfoLevel, msg, mergeFields(fields...))
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	l.log(WarnLevel, msg, mergeFields(fields...))
}

// Error logs at error level.
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	l.log(ErrorLevel, msg, mergeFields(fields...))
}

func mergeFields(fields ...map[string]interface{}) map[string]interface{} {
	if len(fields) == 0 {
		return nil
	}
	m := make(map[string]interface{})
	for _, f := range fields {
		for k, v := range f {
			m[k] = v
		}
	}
	return m
}

// --- Package-level functions use defaultLogger ---

func Init(level Level, format string, output string) {
	var out io.Writer
	switch output {
	case "stdout":
		out = os.Stdout
	case "stderr":
		out = os.Stderr
	default:
		f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "log: cannot open %s: %v, using stderr\n", output, err)
			out = os.Stderr
		} else {
			out = f
		}
	}
	defaultLogger = New(level, format, out)
}

func Debug(msg string, fields ...map[string]interface{}) {
	defaultLogger.Debug(msg, fields...)
}
func Info(msg string, fields ...map[string]interface{}) {
	defaultLogger.Info(msg, fields...)
}
func Warn(msg string, fields ...map[string]interface{}) {
	defaultLogger.Warn(msg, fields...)
}
func Error(msg string, fields ...map[string]interface{}) {
	defaultLogger.Error(msg, fields...)
}
