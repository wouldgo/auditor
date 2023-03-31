package logger

import (
	"strconv"
	"strings"

	"github.com/dgraph-io/badger/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	Level LoggingLevel
	Log   *zap.SugaredLogger
}
type LoggingLevel uint32

const (
	DEBUG LoggingLevel = iota
	INFO
	WARNING
	ERROR
)

func LoggingLevelFrom(value string) LoggingLevel {
	switch value {
	case "debug":
	case "DEBUG":
		return DEBUG
	case "info":
	case "INFO":
		return INFO
	case "warn":
	case "WARN":
		return WARNING
	case "error":
	case "ERROR":
		return ERROR
	}

	return DEBUG
}

func (i *LoggingLevel) ToBadger(options badger.Options, logger *Logger) badger.Options {
	innerLog := newInnerLog(*logger)

	switch uint(*i) {
	case uint(DEBUG):
		return options.WithLoggingLevel(badger.DEBUG).WithLogger(innerLog)
	case uint(INFO):
		return options.WithLoggingLevel(badger.INFO).WithLogger(innerLog)
	case uint(WARNING):
		return options.WithLoggingLevel(badger.WARNING).WithLogger(innerLog)
	case uint(ERROR):
		return options.WithLoggingLevel(badger.ERROR).WithLogger(innerLog)
	}

	return options.WithLoggingLevel(badger.DEBUG).WithLogger(innerLog)
}

func (i *LoggingLevel) ToZap() zap.AtomicLevel {
	switch uint(*i) {
	case uint(DEBUG):
		return zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case uint(INFO):
		return zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case uint(WARNING):
		return zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case uint(ERROR):
		return zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	}

	return zap.NewAtomicLevelAt(zapcore.DebugLevel)
}

func (i *LoggingLevel) String() string {
	return strconv.FormatUint(uint64(*i), 10)
}

func (i *LoggingLevel) Set(value string) error {
	thisValue := LoggingLevelFrom(value)
	*i = thisValue
	return nil
}

type innerLog struct {
	sugared *zap.SugaredLogger
}

func newInnerLog(logger Logger) *innerLog {
	return &innerLog{
		sugared: logger.Log,
	}
}

func (l *innerLog) Errorf(template string, rest ...interface{}) {

	l.sugared.Errorf(strings.TrimSuffix(template, "\n"), rest...)
}
func (l *innerLog) Warningf(template string, rest ...interface{}) {
	l.sugared.Warnf(strings.TrimSuffix(template, "\n"), rest...)
}
func (l *innerLog) Infof(template string, rest ...interface{}) {
	l.sugared.Infof(strings.TrimSuffix(template, "\n"), rest...)
}
func (l *innerLog) Debugf(template string, rest ...interface{}) {
	l.sugared.Debugf(strings.TrimSuffix(template, "\n"), rest...)
}
