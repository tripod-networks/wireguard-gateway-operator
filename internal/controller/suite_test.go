package controller

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"

	wgnetv1alpha1 "github.com/tripod-networks/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// testEnv bundles a running envtest control plane and a client wired to the
// operator's scheme, shared by the controller tests in this package.
type testEnv struct {
	env            *envtest.Environment
	cfg            *rest.Config
	client         client.Client
	scheme         *runtime.Scheme
	operatorCfg    *rest.Config
	operatorClient client.Client
}

// gatewayCRDPath is the controller-gen-emitted Gateway CRD, loaded into the test
// API server so the typed client can create Gateways.
func gatewayCRDPath() string {
	return filepath.Join("..", "..", "k8s", "charts", "wireguard-gateway-operator", "templates", "crds")
}

// setupEnvtest starts a control plane with the Gateway CRD plus minimal XGatewayGCP and
// DNSEndpoint CRDs. It skips the test when KUBEBUILDER_ASSETS is unset.
func setupEnvtest(t *testing.T) *testEnv {
	t.Helper()

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS unset; run `make envtest` and export it to exercise the envtest path")
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(wgnetv1alpha1.AddToScheme(scheme))

	env := &envtest.Environment{
		Scheme:                scheme,
		ErrorIfCRDPathMissing: true,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths: []string{gatewayCRDPath()},
			CRDs: []*apiextensionsv1.CustomResourceDefinition{
				minimalXGatewayGCPCRD(), minimalXGatewayNetworkCRD(), minimalDNSEndpointCRD(),
				minimalSecretManagerCRD("secrets", "Secret", "SecretList"),
				minimalSecretManagerCRD("secretversions", "SecretVersion", "SecretVersionList"),
				minimalSecretManagerCRD("secretiammembers", "SecretIAMMember", "SecretIAMMemberList"),
			},
		},
	}

	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	return &testEnv{env: env, cfg: cfg, client: c, scheme: scheme}
}

// setupEnvtestRBAC binds the operator's generated ClusterRole to a real client-certificate
// identity, so a reconcile is authorized exactly as the deployed operator is.
func setupEnvtestRBAC(t *testing.T) *testEnv {
	t.Helper()
	te := setupEnvtest(t)
	ctx := context.Background()

	role := loadOperatorClusterRole(t)
	if err := te.client.Create(ctx, role); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create operator ClusterRole: %v", err)
	}

	// The operator binds this ClusterRole per Local Gateway under a bind grant scoped to its
	// name. Built in Go because the shipped chart template is Helm-templated.
	linkRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-link-endpointslice-reader"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{"discovery.k8s.io"},
			Resources: []string{"endpointslices"},
			Verbs:     []string{"get", "list", "watch"},
		}},
	}
	if err := te.client.Create(ctx, linkRole); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create link endpointslice-reader ClusterRole: %v", err)
	}

	const operatorUser = "wireguard-gateway-operator-test"
	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: operatorUser},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: operatorUser, APIGroup: "rbac.authorization.k8s.io"}},
	}
	if err := te.client.Create(ctx, binding); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("create operator ClusterRoleBinding: %v", err)
	}

	// Mint a real client-certificate identity so tests authenticate via the operator's
	// actual auth path rather than an impersonation header.
	user, err := te.env.AddUser(envtest.User{Name: operatorUser, Groups: []string{"system:authenticated"}}, te.cfg)
	if err != nil {
		t.Fatalf("add operator user: %v", err)
	}
	opCfg := user.Config()
	opClient, err := client.New(opCfg, client.Options{Scheme: te.scheme})
	if err != nil {
		t.Fatalf("build operator client: %v", err)
	}
	te.operatorCfg = opCfg
	te.operatorClient = opClient

	waitOperatorRBAC(ctx, t, opClient)
	return te
}

// loadOperatorClusterRole decodes the generated operator ClusterRole from the chart so
// the test binds exactly the shipped permission set (a dropped verb fails these tests).
func loadOperatorClusterRole(t *testing.T) *rbacv1.ClusterRole {
	t.Helper()
	path := filepath.Join("..", "..", "k8s", "charts", "wireguard-gateway-operator", "templates", "role.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read operator role.yaml: %v", err)
	}
	// role.yaml is static controller-gen output; templating it would make Unmarshal
	// bind a role that diverges from what ships.
	if bytes.Contains(data, []byte("{{")) {
		t.Fatalf("operator role.yaml is Helm-templated; loadOperatorClusterRole must render the chart before binding")
	}
	role := &rbacv1.ClusterRole{}
	if err := yaml.Unmarshal(data, role); err != nil {
		t.Fatalf("unmarshal operator role.yaml: %v", err)
	}
	role.ResourceVersion = ""
	return role
}

const rbacPropagationTimeout = 15 * time.Second

// waitOperatorRBAC blocks until the authorizer reflects the binding, so the first reconcile does
// not race propagation. Role and binding are single objects, so one authorized verb suffices.
func waitOperatorRBAC(ctx context.Context, t *testing.T, opClient client.Client) {
	t.Helper()
	pollUntil(ctx, t, rbacPropagationTimeout, "operator RBAC propagation (gateways/list allowed)", func() bool {
		ssar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Group: "wgnet.dev", Resource: "gateways", Verb: "list",
				},
			},
		}
		err := opClient.Create(ctx, ssar)
		return err == nil && ssar.Status.Allowed
	})
}

// newOperatorReconciler wires r's Client and APIReader to the RBAC-scoped operator client, so
// no call site can accidentally keep the admin client.
func newOperatorReconciler(te *testEnv, r *GatewayReconciler) *GatewayReconciler {
	r.Client = te.operatorClient
	r.APIReader = te.operatorClient
	if r.Scheme == nil {
		r.Scheme = te.scheme
	}
	return r
}

// preserveUnknownProps is the open object schema the minimal CRDs use so the
// operator's arbitrary spec/status fields round-trip without a typed schema.
func preserveUnknownProps() *apiextensionsv1.JSONSchemaProps {
	yes := true
	return &apiextensionsv1.JSONSchemaProps{
		Type:                   "object",
		XPreserveUnknownFields: &yes,
	}
}

// minimalXGatewayGCPCRD is a namespaced CRD matching the composite's GVK, enough for the
// reconciler to create the composite and read a patched status.
func minimalXGatewayGCPCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "xgatewaygcps.infra.wgnet.dev"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infra.wgnet.dev",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "XGatewayGCP",
				ListKind: "XGatewayGCPList",
				Plural:   "xgatewaygcps",
				Singular: "xgatewaygcp",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
				Subresources: &apiextensionsv1.CustomResourceSubresources{
					Status: &apiextensionsv1.CustomResourceSubresourceStatus{},
				},
			}},
		},
	}
}

// minimalXGatewayNetworkCRD is a namespaced CRD matching the shared-network composite's GVK,
// enough to apply the singleton network and for the refcount teardown to delete it.
func minimalXGatewayNetworkCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "xgatewaynetworks.infra.wgnet.dev"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "infra.wgnet.dev",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "XGatewayNetwork",
				ListKind: "XGatewayNetworkList",
				Plural:   "xgatewaynetworks",
				Singular: "xgatewaynetwork",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
				Subresources: &apiextensionsv1.CustomResourceSubresources{
					Status: &apiextensionsv1.CustomResourceSubresourceStatus{},
				},
			}},
		},
	}
}

// minimalSecretManagerCRD is a cluster-scoped stand-in CRD for one secretmanager.gcp.m.upbound.io
// managed-resource kind, enough for gcpmembers' confirmation to observe presence or NotFound.
func minimalSecretManagerCRD(plural, kind, listKind string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: plural + ".secretmanager.gcp.m.upbound.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "secretmanager.gcp.m.upbound.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     kind,
				ListKind: listKind,
				Plural:   plural,
				Singular: plural,
			},
			Scope: apiextensionsv1.ClusterScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1beta1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
			}},
		},
	}
}

// minimalDNSEndpointCRD is a namespaced CRD matching external-dns's DNSEndpoint
// GVK with an open schema, so the operator's DNS builder can create it.
func minimalDNSEndpointCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dnsendpoints.externaldns.k8s.io",
			// The API server gates *.k8s.io groups behind an approval annotation;
			// external-dns ships this on its real CRD.
			Annotations: map[string]string{
				"api-approved.kubernetes.io": "https://github.com/kubernetes-sigs/external-dns/pull/2007",
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "externaldns.k8s.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "DNSEndpoint",
				ListKind: "DNSEndpointList",
				Plural:   "dnsendpoints",
				Singular: "dnsendpoint",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name:    "v1alpha1",
				Served:  true,
				Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{
					OpenAPIV3Schema: preserveUnknownProps(),
				},
			}},
		},
	}
}

// eventually polls cond until true or the deadline elapses, failing with msg. envtest has no
// informer cache here, so a poll loop is the way to await asynchronous reconcile effects.
func eventually(ctx context.Context, t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s: context done: %v", msg, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %s", msg)
}
