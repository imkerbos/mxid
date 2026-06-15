package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/imkerbos/mxid/pkg/secure"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// InitLogger creates a zap.Logger based on configuration.
func InitLogger(cfg *LogConfig) (*zap.Logger, error) {
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	var encoder zapcore.Encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "ts"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	if cfg.Format == "text" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var writeSyncer zapcore.WriteSyncer
	if cfg.Output == "file" && cfg.FilePath != "" {
		dir := filepath.Dir(cfg.FilePath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.AddSync(f)
	} else {
		writeSyncer = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewCore(encoder, writeSyncer, level)
	// Wrap with the redacting filter so any field whose key matches
	// password / secret / token patterns gets replaced with "***" before
	// encoding. Defense-in-depth: code that knows it is touching a
	// secret should use secure.Secret explicitly; this is a tripwire.
	core = secure.NewRedactingCore(core)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}
