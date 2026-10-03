// Command gateway-operator is the controller-runtime manager that runs the
// GatewayReconciler. It reconciles user-facing Gateway CRs into their Crossplane
// XGatewayGCP composite, WireGuard key Secrets, the in-cluster link Deployment and
// RBAC, and an optional DNSEndpoint.
package main

import (
	"os"

	"github.com/go-logr/zapr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/tripod-networks/wireguard-gateway-operator/internal/config"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/controller"
	"github.com/tripod-networks/wireguard-gateway-operator/internal/logger"
	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// leaderElectionID is the stable lock name the operator's leader election uses.
// Held in the operator's namespace so a single replica reconciles at a time.
const leaderElectionID = "gateway-operator-leader"

// managerConfig holds manager-runtime knobs distinct from the reconciler's domain
// Config: leader election and metrics/health bind addresses, populated via config.Load.
type managerConfig struct {
	// LeaderElection enables single-active-replica reconciliation via a Lease.
	LeaderElection bool `envconfig:"GATEWAY_OPERATOR_LEADER_ELECTION" default:"true"`
	// MetricsBindAddress is the metrics server address; "0" disables it.
	MetricsBindAddress string `envconfig:"GATEWAY_OPERATOR_METRICS_ADDR" default:":8080"`
	// HealthProbeBindAddress is the healthz/readyz address.
	HealthProbeBindAddress string `envconfig:"GATEWAY_OPERATOR_HEALTH_ADDR" default:":8081"`
}

// cacheOptions limits cached kinds to link children; unscoped, the cache would hold every
// ServiceAccount/Role/RoleBinding/ClusterRoleBinding, growing with the cluster, not the operator.
func cacheOptions() cache.Options {
	linkObjects := cache.ByObject{Label: controller.LinkCacheSelector()}
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&corev1.ServiceAccount{}:     linkObjects,
			&rbacv1.Role{}:               linkObjects,
			&rbacv1.RoleBinding{}:        linkObjects,
			&rbacv1.ClusterRoleBinding{}: linkObjects,
		},
	}
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	logCfg, err := config.Load[logger.Config]()
	if err != nil {
		return err
	}

	log, err := logger.New(logCfg)
	if err != nil {
		return err
	}
	defer log.Sync() //nolint:errcheck

	ctrl.SetLogger(zapr.NewLogger(log.Desugar()))

	mgrCfg, err := config.Load[managerConfig]()
	if err != nil {
		log.Errorw("load manager config", "error", err)
		return err
	}
	reconcilerCfg, err := config.Load[controller.Config]()
	if err != nil {
		log.Errorw("load reconciler config", "error", err)
		return err
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wgnetv1alpha1.AddToScheme(scheme))

	options := ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: mgrCfg.MetricsBindAddress},
		HealthProbeBindAddress:  mgrCfg.HealthProbeBindAddress,
		LeaderElection:          mgrCfg.LeaderElection,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: reconcilerCfg.PodNamespace,
		Cache:                   cacheOptions(),
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		log.Errorw("create manager", "error", err)
		return err
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Errorw("add healthz check", "error", err)
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Errorw("add readyz check", "error", err)
		return err
	}

	reconciler := &controller.GatewayReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Config:   reconcilerCfg,
		Recorder: mgr.GetEventRecorder("gateway-operator"),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		log.Errorw("set up reconciler", "error", err)
		return err
	}

	log.Infow("starting manager",
		"leaderElection", mgrCfg.LeaderElection,
		"metricsAddr", mgrCfg.MetricsBindAddress,
		"healthAddr", mgrCfg.HealthProbeBindAddress,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Errorw("manager exited", "error", err)
		return err
	}
	return nil
}
