// Command gateway-link is the in-cluster link daemon. It brings up the WireGuard
// tunnel to the gateway VM and programs nftables to forward configured ports either to
// in-cluster Services (Cluster mode) or, in Local mode, to ready backend pods on its
// own node.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/config"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/link"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/logger"
)

func main() {
	logCfg, err := config.Load[logger.Config]()
	if err != nil {
		os.Exit(1)
	}

	log, err := logger.New(logCfg)
	if err != nil {
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	cfg, err := config.Load[link.Config]()
	if err != nil {
		log.Errorw("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := link.Run(ctx, cfg, log); err != nil {
		log.Errorw("gateway-link exited", "error", err)
		os.Exit(1)
	}
}
