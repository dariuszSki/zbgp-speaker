package cmd

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/util/debugz"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	logger  = pfxlog.Logger()
	rootCmd = &cobra.Command{
		Use:  "iptables-bgp-scraper",
		Long: "an app that scrapes iptables rules for Ziti Services under NF-INTERCEPTS Chain, then utilizes gobgp server to advertize scraped prefixes to bgp neighbors.",
		Run:  zlogs,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	options := pfxlog.DefaultOptions().SetTrimPrefix("github.com/netfoundry/ziti-bgp").SetAbsoluteTime().Color()
	options.DataFielder = func(v interface{}, l *logrus.Entry) *logrus.Entry {
		cd, ok := v.(*contextLogData)
		if ok {
			return l.WithFields(map[string]interface{}{
				"topic": cd.topic,
				"value": cd.value,
			})
		} else {
			return l.WithFields(nil)
		}
	}
	pfxlog.GlobalInit(logrus.InfoLevel, options)
	debugz.AddStackDumpHandler()
	rootCmd.PersistentFlags().StringP("log-level", "l", "Info", "specifying log level")
}

func zlogs(cmd *cobra.Command, args []string) {
	LogLevel, _ := cmd.Flags().GetString("log-level")

	switch LogLevel {
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

type zLogger struct {
	logger *pfxlog.Builder
}

func (l *zLogger) Panic(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *zLogger) Fatal(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *zLogger) Error(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *zLogger) Warn(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *zLogger) Info(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *zLogger) Debug(msg string, fields log.Fields) {
	l.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *zLogger) SetLevel(level log.LogLevel) {
	logrus.SetLevel(logrus.Level(level))
}

func (l *zLogger) GetLevel() log.LogLevel {
	return log.LogLevel(l.logger.Level)
}
