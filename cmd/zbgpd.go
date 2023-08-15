package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-systemd/daemon"
	"github.com/osrg/gobgp/v3/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func stopServer(s *server.BgpServer, useSdNotify bool) {
	logger.Info("stopping gobgpd server")

	s.Stop()
	if useSdNotify {
		_, err := daemon.SdNotify(false, daemon.SdNotifyStopping)
		if err != nil {
			return
		}
	}
}

func zgbpd(opts OptsGobgpd) {

	/* watch for os signal interrupts to clean up resources and exit gracefully */
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	maxSize := 256 << 20
	grpcOpts := []grpc.ServerOption{grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize)}
	logger.Info(opts.GrpcHosts)
	logger.Info("gobgpd started")
	s := server.NewBgpServer(server.GrpcListenAddress(opts.GrpcHosts), server.GrpcOption(grpcOpts), server.LoggerOption(&zLogger{logger: logger}))
	go s.Serve()

	if opts.UseSdNotify {
		if status, err := daemon.SdNotify(false, daemon.SdNotifyReady); !status {
			if err != nil {
				logger.Warnf("Failed to send notification via sd_notify(): %s", err)
			} else {
				logger.Warnf("The socket sd_notify() isn't available")
			}
		}
	}
	if opts.ConfigFile == "" {
		logger.Error("Configuration file not provided")
		stopServer(s, opts.UseSdNotify)
		os.Exit(0)
	}

	/* Read the config file for the gobgp server */
	initialConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
	if err != nil {
		logger.Data(&ContextLogData{"Config", err}).Fatalf(
			"Can't read config file %s", opts.ConfigFile)
	}
	logger.Data(&ContextLogData{"Config", nil}).Info("Finished reading the config file")
	/* Apply the configs to the gobgp server */
	currentConfig, err := config.InitialConfig(context.Background(), s, initialConfig, opts.GracefulRestart)
	if err != nil {
		logger.Data(&ContextLogData{"Config", err}).Fatalf(
			"Failed to apply initial configuration %s", opts.ConfigFile)
	}
	for sig := range sigCh {

		if sig != syscall.SIGHUP {
			stopServer(s, opts.UseSdNotify)
			os.Exit(1)
		}

		logger.WithFields(logrus.Fields{
			"Topic": "Config",
		}).Info("Reload the config file")
		newConfig, err := config.ReadConfigFile(opts.ConfigFile, opts.ConfigType)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Can't read config file %s", opts.ConfigFile)
			continue
		}

		currentConfig, err = config.UpdateConfig(context.Background(), s, currentConfig, newConfig)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Failed to update config %s", opts.ConfigFile)
			continue
		}
	}

}
