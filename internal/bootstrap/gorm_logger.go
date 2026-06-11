package bootstrap

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	gormlogger "gorm.io/gorm/logger"
)

// zapGormLogger adapts zap.Logger to GORM's logger interface.
type zapGormLogger struct {
	logger   *zap.Logger
	level    gormlogger.LogLevel
	slowSQL  time.Duration
}

// NewGormLogger creates a GORM logger backed by zap.
func NewGormLogger(logger *zap.Logger, level gormlogger.LogLevel) gormlogger.Interface {
	return &zapGormLogger{
		logger:  logger.Named("gorm"),
		level:   level,
		slowSQL: 200 * time.Millisecond,
	}
}

func (l *zapGormLogger) LogMode(level gormlogger.LogLevel) gormlogger.Interface {
	return &zapGormLogger{
		logger:  l.logger,
		level:   level,
		slowSQL: l.slowSQL,
	}
}

func (l *zapGormLogger) Info(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Info {
		l.logger.Info(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Warn(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Warn {
		l.logger.Warn(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Error(_ context.Context, msg string, data ...any) {
	if l.level >= gormlogger.Error {
		l.logger.Error(fmt.Sprintf(msg, data...))
	}
}

func (l *zapGormLogger) Trace(_ context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	if l.level <= gormlogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	fields := []zap.Field{
		zap.Duration("elapsed", elapsed),
		zap.Int64("rows", rows),
		zap.String("sql", sql),
	}

	switch {
	case err != nil && l.level >= gormlogger.Error:
		l.logger.Error("query error", append(fields, zap.Error(err))...)
	case elapsed > l.slowSQL && l.level >= gormlogger.Warn:
		l.logger.Warn("slow query", fields...)
	case l.level >= gormlogger.Info:
		l.logger.Debug("query", fields...)
	}
}
