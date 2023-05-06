package common

import (
	"os"

	"go.uber.org/zap"
)

func initZapLogger() *zap.Logger {
	switch GSCAN_LOG_LEVEL {
	case "development":
		logger, err := zap.NewDevelopment()
		if err != nil {
			panic(err)
		}
		return logger
	case "production":
		fallthrough
	default:
		logger, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}
		return logger
	}
}

var (
	logger          *zap.Logger = initZapLogger()
	GSCAN_LOG_LEVEL             = os.Getenv("GSCAN_LOG_LEVEL")
)

func GetLogger() *zap.Logger {
	if GSCAN_LOG_LEVEL != os.Getenv("GSCAN_LOG_LEVEL") {
		GSCAN_LOG_LEVEL = os.Getenv("GSCAN_LOG_LEVEL")
		*logger = *initZapLogger()
	}
	return logger
}
