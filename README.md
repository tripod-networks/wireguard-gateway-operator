# wireguard-gateway-operator

[![CI](https://github.com/tripod-networks/wireguard-gateway-operator/actions/workflows/ci.yaml/badge.svg)](https://github.com/tripod-networks/wireguard-gateway-operator/actions/workflows/ci.yaml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE) ![Go](https://img.shields.io/github/go-mod/go-version/tripod-networks/wireguard-gateway-operator)

A Kubernetes operator that runs WireGuard gateways on cloud VMs to give a private
or NAT'd cluster public ingress without exposing a cloud LoadBalancer of its own.
You apply a namespaced `Gateway` custom resource and the operator provisions a
dedicated gateway VM, dials it from inside the cluster, and forwards the public
TCP/UDP ports you list to your in-cluster Services. GCP is the cloud backend
implemented today.

Use it when a cluster cannot accept inbound connections directly: on-prem or
NAT'd clusters, a homelab behind a residential ISP, anything with outbound-only
egress. You still get stable public endpoints in front of cluster workloads.

## How it works

Each `Gateway` reconciles two halves. A Crossplane composition provisions a GCP
VM running WireGuard and nftables: it holds the public IP and opens the listed
ports. An in-cluster `gateway-link` peers with that VM and DNATs the forwarded
ports to the backends. Because the cluster only ever dials outbound, no inbound
firewall rule is needed cluster-side. When `dnsHostnames` is set, the operator
publishes a `DNSEndpoint` pointing those names at the VM's public IP for
external-dns to serve.

`spec.trafficPolicy` picks the shape of that in-cluster half. `Cluster`, the
default, runs the link as a Deployment: the tunnel terminates in the link pod's
own network namespace, each forwarded port is DNAT'd to the backend Service's
ClusterIP, and the backend sees the link as the client. `Local` runs the link as
a hostNetwork DaemonSet and terminates the tunnel in the node's network
namespace: one node holds a Lease, DNATs each public port to a ready backend pod
on that node, and routes the replies back into the tunnel through a per-Gateway
`ip rule` matching the connmark set on the tunnel's ingress. Every per-Gateway name
and number a Local link programs on the node — tunnel interface, nftables table,
firewall mark, route table — derives from the id in `status.link.id`, so several
Local Gateways coexist on one node. The operator also records that id in the
`wgnet.dev/link-id` annotation and reads it back when status is empty, so a
Gateway restored without its status keeps its id and the node state it names.

A minimal `Gateway`:

```yaml
apiVersion: wgnet.dev/v1alpha1
kind: Gateway
metadata:
  name: edge
  namespace: my-app
spec:
  gcp:
    projectID: my-gcp-project
    region: us-central1
    zone: us-central1-a
  forwards:
    - port: 443
      protocol: TCP
      service: my-app
```

This gives `my-app` a public endpoint on a cloud VM that forwards port 443 to the
in-cluster Service. See [Creating a gateway](#creating-a-gateway) for the full
spec.

The `Cluster` path:

```
            client
               │
               │  public internet
               ▼
┌─────────────────────────────┐
│  cloud gateway VM           │
│  public IP : port           │
│  WireGuard + nftables       │
└──────────────┬──────────────┘
               │  WireGuard tunnel
               │  (cluster dials outbound)
               ▼
┌─────────────────────────────┐
│  gateway-link Deployment    │
│  DNAT port → targetPort     │
└──────────────┬──────────────┘
               │  ClusterIP
               ▼
       backend Service ──▶ pods
```

The `Local` path, from the tunnel down:

```
               │  WireGuard tunnel
               ▼
┌─────────────────────────────┐
│  active node's netns        │
│  gateway-link DaemonSet     │
│  DNAT port → backend pod IP │
└──────────────┬──────────────┘
               │  pod IP on this node
               ▼
        backend pod
```

## Cloud backends

Gateway-VM provisioning is backend-specific, and only GCP exists today.

| Backend | Status |
|---|---|
| GCP | Implemented |
| AWS | Not yet implemented |

## Prerequisites

| Requirement | Notes | Docs |
| --- | --- | --- |
| Kubernetes cluster + kubectl | Any conformant cluster; typically one that cannot expose its own LoadBalancer. | [kubectl](https://kubernetes.io/docs/tasks/tools/) |
| Privileged pods in gateway namespaces | The link container runs as root with `NET_ADMIN` in both traffic policies. `Cluster` adds a privileged init container that enables IPv4 forwarding in the pod's network namespace; `Local` has no init container and instead needs `hostNetwork` plus a read-write hostPath mount of the node's `/proc/sys/net`. Either way the namespace where you create a Gateway must not enforce restricted/baseline PodSecurity (label it `pod-security.kubernetes.io/enforce: privileged` if your cluster defaults to enforcement). | [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) |
| Loose `rp_filter` on Local-mode nodes | A node that runs a Local-mode link needs `net.ipv4.conf.all.rp_filter` set to 0 or 2. The link lowers only the tunnel interface's own value and never the node-wide one, and the kernel takes the maximum of the two. A node that fails this reports `RPFilterStrict` on the Gateway's `Ready` condition. The link also programs a `throw` route per backend pod IP in the Gateway's route table, so a marked reply's reverse-path lookup falls through to the main table and passes validation on the pod-facing interface even where `net.ipv4.conf.all.src_valid_mark` is 1 and that interface's `rp_filter` is strict. | [rp_filter](https://docs.kernel.org/networking/ip-sysctl.html) |
| Exclusive packet-mark bits on Local-mode nodes | A Local-mode link claims the upper 16 bits of the packet mark and of the conntrack mark on the nodes it may run on, mask `0xffff0000`. It marks each tunnel connection with `<link id> << 16`, restores that value into the mark of reply packets, and steers them with `ip rule fwmark <link id> << 16/0xffff0000`. `status.link.id` is 1..250, so the values themselves sit in bits 16-23. Every other mark user on the node must leave that mask untouched: check your CNI's packet-mark mask, and any service mesh or policy routing that marks packets. An overlap routes foreign packets into the tunnel or misroutes the link's replies. | [ip rule](https://man7.org/linux/man-pages/man8/ip-rule.8.html) |
| Helm | Installs Crossplane core and the operator chart. | [Helm](https://helm.sh/docs/intro/install/) |
| Crossplane | Installed in the cluster; realizes the gateway VM composition. | [Crossplane install](https://docs.crossplane.io/latest/get-started/install/) |
| GCP provider (installed) | The Upbound provider-gcp packages, installed via Crossplane's package mechanism. | [Crossplane providers](https://docs.crossplane.io/latest/packages/providers/) |
| GCP provider (configured) | A `ClusterProviderConfig` with `credentials.source=Secret` referencing a service-account key. | [Provider authentication](https://docs.upbound.io/manuals/packages/providers/authentication/) |
| GCP project + APIs | A project with billing and the compute, secretmanager, iam, and cloudresourcemanager APIs enabled. | [gcloud CLI](https://docs.cloud.google.com/sdk/docs/install) |
| GCP service-account key | A JSON key for a service account with the roles the composition needs, delivered as the Secret the `ClusterProviderConfig` references. | [Create SA key](https://docs.cloud.google.com/iam/docs/keys-create-delete) |
| OS Login IAM (optional) | Only for break-glass SSH to a gateway VM: grant the SSH caller `roles/compute.osLogin` (or `roles/compute.osAdminLogin`) plus IAP tunnel access on the project. Gateways provision without it. | [OS Login](https://docs.cloud.google.com/compute/docs/oslogin) |

## Installation

Install the upstream dependencies in order: Crossplane core, the GCP providers
and pipeline functions, then credentials and a `ClusterProviderConfig`. Finish
with the operator. The charts under `k8s/infra/crossplane/`
(`crossplane-providers`, `crossplane-config`) are E2E test scaffolding: they pin
package versions and add a CRD-readiness gate Job for `make test-e2e`, and are
not a production install path.

**1. Crossplane core.**

```sh
helm install crossplane crossplane \
  --repo https://charts.crossplane.io/stable \
  -n crossplane-system --create-namespace --wait
```

**2. GCP providers and pipeline functions.**

```sh
kubectl apply -f - <<'EOF'
apiVersion: pkg.crossplane.io/v1beta1
kind: DeploymentRuntimeConfig
metadata:
  name: gcp-fast-poll
spec:
  deploymentTemplate:
    spec:
      selector: {}
      template:
        spec:
          containers:
            - name: package-runtime
              env:
                - name: PROVIDER_POLL
                  value: "30s"
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-compute
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-compute:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-cloudplatform
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-cloudplatform:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-gcp-secretmanager
spec:
  package: xpkg.upbound.io/upbound/provider-gcp-secretmanager:v2
  runtimeConfigRef:
    name: gcp-fast-poll
---
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: function-go-templating
spec:
  package: xpkg.crossplane.io/crossplane-contrib/function-go-templating:v0.12.1
---
apiVersion: pkg.crossplane.io/v1
kind: Function
metadata:
  name: function-auto-ready
spec:
  package: xpkg.crossplane.io/crossplane-contrib/function-auto-ready:v0.6.5
EOF

kubectl wait --for=condition=Healthy provider.pkg.crossplane.io --all --timeout=5m
kubectl wait --for=condition=Healthy function.pkg.crossplane.io --all --timeout=5m
```

The providers track the floating `:v2` major channel, since Upbound publishes no
`:latest`. The functions pin an explicit version because crossplane-contrib
publishes no floating tag. Confirm current versions on the
[Upbound Marketplace](https://marketplace.upbound.io/) (providers) and the
[crossplane-contrib releases](https://github.com/crossplane-contrib) (functions).

The `gcp-fast-poll` DeploymentRuntimeConfig lowers the provider poll interval,
since the upstream default of 10m makes the multi-resource gateway provisioning
chain slow. Tune `PROVIDER_POLL`: lower is faster to provision at the cost of more
API calls. Do not declare a `provider-family-gcp` Provider explicitly: the leaf
providers pull the shared family in automatically, and declaring it duplicates
the family and breaks its RBAC.

**3. Credentials and ProviderConfig.** Load the service-account key as the
`crossplane-system/gcp-creds` Secret (key `credentials.json`). See
[Configuring GCP credentials](#configuring-gcp-credentials) for obtaining the key
and for the declarative loading paths. The direct form is:

```sh
kubectl create secret generic gcp-creds -n crossplane-system \
  --from-file=credentials.json=/path/to/gcp-key.json

kubectl apply -f - <<'EOF'
apiVersion: gcp.m.upbound.io/v1beta1
kind: ClusterProviderConfig
metadata:
  name: default
spec:
  projectID: YOUR_GCP_PROJECT_ID
  credentials:
    source: Secret
    secretRef:
      namespace: crossplane-system
      name: gcp-creds
      key: credentials.json
EOF
```

The `ClusterProviderConfig` name must match the operator's configured provider
config (Helm `operator.providerConfigName` / env `GATEWAY_PROVIDER_CONFIG_NAME`,
default `default`): the gateway composition's GCP managed resources reference it
as `providerConfigRef.name`. It and the provider CRDs must exist before any
`Gateway` provisions.

The operator reads the same `crossplane-system/gcp-creds` Secret directly for
read-only membership discovery on load-balanced Gateways; no second Secret or
additional RBAC is required. The existing ClusterRole already grants `get` on
secrets cluster-wide. The operator's credential reading is configured via Helm
`gcp.credentialsSecret` (namespace, name, key) and mapped to env vars
`GATEWAY_GCP_CREDENTIALS_SECRET` and `GATEWAY_GCP_CREDENTIALS_KEY`, but the
defaults match the standard provider setup.

For a load-balanced Gateway the operator re-lists the MIG's members every
`gcp.discoveryInterval` (default `30s`) and re-reads each member's details every
`gcp.addressRefreshInterval` (default `10m`) to catch an address change the
listing missed. The env vars are `GATEWAY_GCP_DISCOVERY_INTERVAL` and
`GATEWAY_GCP_ADDRESS_REFRESH_INTERVAL`.

**4. The operator.**

```sh
helm install wireguard-gateway-operator \
  oci://ghcr.io/tripod-networks/wireguard-gateway-operator/charts/wireguard-gateway-operator \
  --version 0.10.0 \
  -n wireguard-gateway-operator --create-namespace
```

The published chart pins the operator and link images, so no image values are
needed; override `operator.image` / `link.image` only if mirroring the images
elsewhere. The GCP project is set per Gateway via `spec.gcp.projectID`,
not on the chart. The two images are built from this repo's `Dockerfile`
(`make docker-build-operator` and `make docker-build`, override `OPERATOR_IMAGE` /
`IMAGE` to push registry-qualified tags).

## Configuring GCP credentials

The provider authenticates to GCP with a service-account JSON key. This section
covers minting that key; loading it as the Secret is step 4 below.

The exported key is long-lived and the scripts do not rotate it. Periodically
mint a replacement (`gcloud iam service-accounts keys create`), update the Secret,
and delete the old key.

1. Create a GCP project and enable the required APIs: compute, secretmanager,
   iam, cloudresourcemanager.
2. Create a service account and grant it the roles the composition needs
   (`compute.instanceAdmin.v1`, `compute.networkAdmin`, `compute.securityAdmin`,
   `iam.serviceAccountAdmin`, `iam.serviceAccountUser`, `logging.viewer`,
   `secretmanager.admin`).
3. Create a JSON key for that service account.
4. Load the key into the cluster as the Secret above, using your cluster's
   declarative secret mechanism (External Secrets Operator, Sealed Secrets,
   or GitOps). The `ClusterProviderConfig` then reads it.

`scripts/setup-gcp-project.sh` performs step 1 (project and APIs),
`scripts/setup-gcp-sa.sh` performs step 2 (the service account and its roles),
and `scripts/get-gcp-creds.sh` performs step 3 (the key). All read configuration
from a `.env` file (see [.env.example](.env.example)). They produce the GCP-side
credential but intentionally do not load it into a cluster. That is step 4.

Reference: [create project](https://docs.cloud.google.com/resource-manager/docs/creating-managing-projects),
[enable APIs](https://docs.cloud.google.com/service-usage/docs/enable-disable),
[create service account](https://docs.cloud.google.com/iam/docs/service-accounts-create),
[create SA key](https://docs.cloud.google.com/iam/docs/keys-create-delete).

## Creating a gateway

Apply a `Gateway` in the namespace whose Services you want to expose. `provider`
defaults to `gcp`. Each forward names a public `port`, a `protocol`, the bare
in-cluster `service` name, and an optional `targetPort` (defaults to `port`).

`spec.gcp` holds the GCP placement: `projectID` (required), `region` (required),
`zone` (required), and the defaulted `machineType`, `image`, `diskSizeGB`,
`address`, and `spot`. `address` selects the VM's public ingress address; see
below. `spec.wireguard` holds the tunnel
parameters, all defaulted: `listenPort` (the gateway VM's WireGuard UDP port,
range 1–65535), `subnet`, `gatewayAddress`, `linkAddress`, `keepalive`, `mtu`,
and `reconcileInterval`. An omitted `spec.wireguard` yields the standard tunnel.
`spec.trafficPolicy` selects the data path, `Cluster` by default; see
[Traffic policy](#traffic-policy). `spec.link` configures the link workload:
`replicas` and a `nodeSelector` applied to its pod template. `spec.responder`
configures the per-Gateway responder: `image` (optional, defaults to the
operator's `GATEWAY_RESPONDER_IMAGE`), `port` (optional, 1–65535, defaults to
`27000`; the port the responder listens on and the health DNAT targets),
`replicas` (optional, defaults to `2`, `Cluster` only — rejected under
`Local`, which runs one pod per node instead), and `resources` (optional, a
`corev1.ResourceRequirements` for the responder container).

```yaml
apiVersion: wgnet.dev/v1alpha1
kind: Gateway
metadata:
  name: edge
  namespace: my-app
spec:
  gcp:
    projectID: my-gcp-project
    region: us-central1
    zone: us-central1-a
    machineType: e2-small
  forwards:
    - port: 443
      protocol: TCP
      service: my-app
      targetPort: 8443
    - port: 80
      protocol: TCP
      service: my-app
      targetPort: 8081
  wireguard:
    listenPort: 51820
  dnsHostnames:
    - edge.example.com
```

```sh
kubectl apply -f gateway.yaml
kubectl get gateway -n my-app
```

```
NAME   ADDRESS         READY   POLICY
edge   203.0.113.42    True    Cluster
```

Forward validation is enforced at apply time and rejected by the Kubernetes API
server:

- Each forward's `(port, protocol)` combination must be unique.
- A UDP forward must not use `spec.wireguard.listenPort`.
- Under `trafficPolicy: Cluster`, a TCP forward must not use the link's health
  port, `spec.link.healthPort` (`27000` when unset).
- At most 64 forwards per Gateway.

Every Gateway's `metadata.name` is at most 53 characters and must be a
DNS-1035 label (lowercase alphanumerics and hyphens, starting with a letter).

`spec.link.healthPort` is Cluster only and defaults to `27000`: it is the port
the cloud health check and the MIG autohealer probe on the VM, and the port
the link DNATs the tunnel's health traffic to the responder. It is mutable
and reserved from TCP forwards.

Under `Local`, `spec.link.healthPort` is rejected and the health port is
`27000` plus `status.link.id` instead. The id is assigned by the operator
after apply, so a TCP forward on that port fails at reconcile with
`ReservedHealthPort`.

The `ADDRESS` column is the gateway's public IP, mirrored onto `status.address`
once provisioning completes. For `type: External` it is the address reserved
outside the operator. For a load-balanced Gateway it is the forwarding rule's
address; each member's own IP is in `status.gcp.members[].externalAddress`.

`READY` reflects the `Ready` condition and `POLICY` the traffic policy.
`kubectl get gateway -o wide` adds `NODE`, the node holding the link Lease. With
`dnsHostnames` set and external-dns running, the listed names resolve to
`ADDRESS`.

`spec.gcp.address` selects where the gateway VM's public ingress address comes
from, `Reserved` by default:

```yaml
spec:
  gcp:
    address:
      type: Reserved   # or: Ephemeral
---
spec:
  gcp:
    address:
      type: External
      external:
        name: prod-edge-ip   # a GCP regional Address resource name
---
spec:
  gcp:
    address:
      type: External
      external:
        ip: 203.0.113.42     # a literal reserved external IPv4
```

For `type: External`, the address must already exist in `spec.gcp.projectID` /
`spec.gcp.region`; the operator never creates or deletes it.

**Upgrading**: a Gateway that carried `reservedIP: false` reads as
`address.type: Reserved` after the CRD upgrade and is given a new reserved
address on its next reconcile. Set `address.type: Ephemeral` explicitly to keep
the old behaviour.

## Load balancing

A Gateway can be deployed as a single instance (the default) or as a regional
managed instance group (MIG) behind a passthrough network load balancer. The
single-instance path carries no configuration: set `spec.gcp.replicas: 1` (or omit
it) and no `spec.gcp.loadBalancer` field. On a single-instance Gateway,
`diskSizeGB` is set at creation and immutable; a load-balanced Gateway rolls a
disk-size change out as a template revision.

The load-balanced path, down to the tunnel:

```
            client
               │
               │  public internet
               ▼
┌─────────────────────────────┐
│  forwarding rule            │
│  status.address, all ports  │
│  healthy VMs only           │
└──────┬───────┬───────┬──────┘
       │       │       │  one VM per replica,
       ▼       ▼       ▼  spread over the zones
    ┌─────┐ ┌─────┐ ┌─────┐
    │ VM  │ │ VM  │ │ VM  │
    └──┬──┘ └──┬──┘ └──┬──┘
       │       │       │  a WireGuard tunnel per VM
       └───────┼───────┘  (cluster dials each VM's own IP)
               ▼
┌─────────────────────────────┐
│  gateway-link, one peer     │
│  per member slot            │
└──────────────┬──────────────┘
               │
               ▼
     Cluster or Local path above
```

To opt into load balancing, set `spec.gcp.loadBalancer` (at creation; it is
immutable). A load-balanced Gateway's `metadata.name` is at most 37 characters:
the instance template name prefix appends a 17-character revision suffix and GCP
caps the prefix at 54. The MIG spreads across the zones in `spec.gcp.zones`,
which must all be in `spec.gcp.region`; if omitted, a single zone is implied:

```yaml
spec:
  gcp:
    replicas: 2
    zones:
      - us-west1-a
      - us-west1-b
    loadBalancer:
      sessionAffinity: NONE  # or: CLIENT_IP, CLIENT_IP_PROTO, CLIENT_IP_PORT_PROTO
```

The effective zone set (computed from `zones` if present, otherwise the single
`zone`) is immutable: once created, the MIG cannot gain or lose zones, though
`replicas` can scale within them. `spec.wireguard.subnet`, `gatewayAddress` and
`linkAddress` are immutable on a load-balanced Gateway too: each member's key
bundle is written once and carries its tunnel address and the link address.

`replicas` is capped by the tunnel address capacity. A `/29` has five member
slots: slot 0 takes `gatewayAddress`, and only the link address is excluded. The
load balancer distributes traffic across live instances; `status.gcp.members`
tracks each member's observed state:

```yaml
status:
  gcp:
    members:
    - name: wgnet-gw-ab12cd-a      # instance name
      zone: us-west1-a
      slot: 0                       # member slot in the MIG
      tunnelAddress: 10.99.0.3/29   # this member's tunnel address
      externalAddress: 203.0.113.1  # its public IP
      instanceID: "1234567890"      # GCP-assigned instance id
      revision: "1"                 # template revision the member runs: the last path segment of the instance template named by the MIG version
      state: Active                 # Pending, Active, Recreating, Departing, or Departed
```

`state` is one of:

| State | Meaning |
| --- | --- |
| `Pending` | In the MIG's list but without a slot yet, because GCP has not assigned it an instance id or because every slot is taken. |
| `Active` | Listed, with a slot, a tunnel address and its own keypair. |
| `Recreating` | Being recreated by the MIG. Keeps its slot, key, address and peer. |
| `Departing` | Missing from the last one or two listings. Keeps its slot, key, address and peer. |
| `Departed` | Missing from three listings in a row, or listed as `DELETING` or `ABANDONING`. The peer is removed; the slot is freed once its cloud resources are gone. If it shows up again it goes back to `Active` on the same slot. |

GCP health-checks every member at `/forwarded-healthz` on the health port,
over the same path client traffic takes: the VM DNATs the probe to the tunnel
address exactly as it does a forward. The link never answers the probe
itself. In `Local` mode the holder DNATs the health port to the responder pod
on its own node; in `Cluster` mode the link DNATs it to the responder
Service's ClusterIP, the same path its forwards take. The reply returns
through the tunnel either way. A 200 there proves the VM, its DNAT, the
tunnel, the link and the pod network all work.

Each Gateway owns its responder, in the Gateway's own namespace and named
`<gateway>-responder`: a Deployment of `spec.responder.replicas` pods under
`trafficPolicy: Cluster`, or a DaemonSet with one pod per node under
`trafficPolicy: Local`, plus a ClusterIP Service of the same name. Both are
owned by the Gateway and deleted with it.

A Gateway's `ResponderMissing` condition goes `True` while a responder is
missing, and a Warning event is emitted; its data plane is still applied
without the health DNAT. In `Local` mode it names the link-pod nodes with no
ready responder pod (reason `NoResponderOnNode`). In `Cluster` mode it goes
`True` with reason `NoResponderRunning` while no ready responder pod exists,
and `False` with reason `ResponderPresent` otherwise.

| Chart value | Operator env | Meaning |
| --- | --- | --- |
| `responder.image.repository`, `responder.image.tag` | `GATEWAY_RESPONDER_IMAGE` | Default responder container image; a Gateway's `spec.responder.image` overrides it. |

The load balancer's check runs every 5s and stops sending traffic to a
member after 2 failures. The MIG's autohealing check runs every 30s and
recreates a VM that fails 10 checks in a row (five minutes).

A recreated VM keeps its name, slot, key and address. Autohealing ignores a new
VM for `initialDelaySec`, 900 seconds, while it boots and fetches its key
bundle.

Member addresses are stateful: GCP promotes each to a static address
(`statefulExternalIp` on `nic0`), keeps it through autohealing and rollouts, and
releases it only when the VM is permanently deleted from the group
(`ON_PERMANENT_INSTANCE_DELETION`). A load-balanced Gateway holds one external
address per member plus one for the forwarding rule, all counted against the
region's quota.

Changing `spec.gcp.image`, `machineType`, `diskSizeGB`, `spot`,
`spec.wireguard.listenPort`, `mtu` or the chart's `operator.enableOsLogin`
creates a new instance template revision. Nothing else does: the revision is a
hash of those inputs only, so a value GCP assigns, such as the service-account
email, never rolls the fleet.

The MIG then recreates its VMs on the new template, one per zone at a time
(`replacementMethod: RECREATE`, no surge, `maxUnavailable` equal to the zone
count, spread over the zones). Each VM keeps its name and address. The old
template goes once the MIG reports every VM on the new one.

With `replicas` at least twice the zone count, every zone keeps a serving VM
during a rollout. With `replicas` equal to the zone count, all VMs are recreated
at once and every forward is down until they boot.

## Traffic policy

`spec.trafficPolicy` selects the data path. It is immutable, because the gateway
VM's ruleset is written at first boot: serving an existing workload the other way
means a second Gateway and a DNS move.

| | `Cluster` (default) | `Local` |
| --- | --- | --- |
| Link workload | Deployment, `spec.link.replicas` pods | hostNetwork DaemonSet, one pod per eligible node (`spec.link.replicas` must stay 1) |
| Tunnel terminates in | the link pod's network namespace | the active node's network namespace |
| DNAT target | the backend Service's ClusterIP | a ready backend pod on the active node |
| Backend sees the client as | the link's tunnel address | the real client address, TCP and UDP |
| Backend reachable on | any node, via kube-proxy | the active node only |

In `Local` mode a Lease elects one active node, preferring nodes that carry a
ready backend pod for every forward. `status.link.activeNode` names the holder.
On the active node, pods and host processes that connect to the Gateway's public
address on a forwarded port reach the local backend directly, without leaving the
node. A backend that connects to itself through the public address sees the
node's pod-side address as the client.
When this redirect is first installed for a port, the operator deletes the
connection-tracking entries to the public address on that port, so flows that
started before it are redirected too.

Local mode requires:

- Loose `rp_filter` on every node the link may run on, per
  [Prerequisites](#prerequisites).
- `hostNetwork` and `NET_ADMIN` for the link pod on every node the DaemonSet
  schedules to. Narrow that set with `spec.link.nodeSelector`.
- A ready backend pod on the active node for every forward. A forward without one
  is not programmed and its traffic is dropped; the rest keep serving.
- The upper 16 bits of the packet and conntrack marks, mask `0xffff0000`, free for
  the link on every node it may run on, per [Prerequisites](#prerequisites).

The operator holds cluster-wide `create` and `delete` on ClusterRoleBindings, so it
can bind each `Local` link's ServiceAccount to the chart's
`gateway-link-endpointslice-reader` ClusterRole, which grants the cluster-scoped
EndpointSlice reads the link needs to find backend pods on its node. Kubernetes
escalation prevention limits what it may grant to permissions it holds itself; the
chart satisfies that with a `bind` grant on that one ClusterRole by name.

A Gateway is `Ready=True` once its address is provisioned and the link pod that
holds the Lease reports an established WireGuard tunnel. The pod's readiness
probe succeeds only after a fresh handshake with a peer (in `Local` mode, on any
one of its applied slots). The holder publishes the same tunnel state onto its
Lease, in the `wgnet.dev/tunnel-ready` annotation, in the same write that renews
`holderIdentity`; the operator requires both the holder pod's readiness and that
annotation before it sets `Ready=True`, so a probe that latches ready before the
holder has acquired the Lease cannot make the Gateway Ready on its own. Until
then the condition is `Ready=False`; this table is in precedence order.

| Reason | Policy | Meaning |
| --- | --- | --- |
| `InvalidTunnelAddresses` | both | the subnet, gateway address, or link address is invalid, or the addresses are not distinct usable hosts in the subnet |
| `TargetNamespaceNotFound` | both | the forward's target namespace does not exist |
| `CrossNamespaceForwardDenied` | both | the target namespace does not allow cross-namespace forwards |
| `ServiceNotFound` | both | the forward's backend Service does not exist |
| `UnsupportedServiceType` | both | the backend Service is `ExternalName`, or is headless with `Cluster` policy; a forward accepts a ClusterIP Service or a headless Service with `Local` policy |
| `TargetPortNotListening` | both | the backend Service does not publish the forward's protocol and port |
| `ReservedHealthPort` | `Local` | a TCP forward uses the gateway's health port |
| `NoLocalEndpoint` | `Local` | some forward has no ready backend pod on the active node; the message names each one |
| `RPFilterStrict` | `Local` | the active node's `net.ipv4.conf.all.rp_filter` is neither 0 nor 2 |
| `ApplyFailed` | both | the link could not program the data plane: a command failed or the health server would not bind. In `Local` mode it also covers a node whose `net.ipv4.ip_forward` is 0 or whose pre-check sysctls are unreadable |
| `InsufficientTunnelAddresses` | load-balanced | the requested replicas exceed the tunnel-address capacity |
| `MemberDiscoveryFailed` | load-balanced | member discovery cannot obtain a usable snapshot |
| `MembersNotReady` | load-balanced | no fleet member observed yet, or members exist but the Lease-holder link pod is not Ready |
| `Provisioning` | both | waiting for the address and an active tunnel; the cloud composite's status message follows when there is one |

The `Local` node checks (`rp_filter`, `ip_forward`, sysctl readability) run once at link
start, so after fixing a node restart its link pod for the fault to clear: delete the
pod and the DaemonSet recreates it. A link pod that finds its Gateway's interface
already on the node at start keeps it: the standby tears its held slots down once
a link pod on another node is observed holding the Lease, and applies them again
if this pod acquires the Lease.

`spec.wireguard.linkAddress` (default `10.99.0.2`) may be identical across
Gateways in either mode. A `Local` link assigns it to that Gateway's own tunnel
interface in the node's namespace, and no rule, route or routing rule it installs
selects by that address. The tunnel rules and routes select by interface and
firewall mark; the hairpin DNATs select by the Gateway's public address and the
forwarded port, and the hairpin masquerade by the backend address.

## Cross-namespace forwards

A forward targets a Service in the Gateway's own namespace by default. To forward
into a different namespace, set `forwards[].namespace`, and the target namespace
must opt in by carrying the label `wgnet.dev/allow-gateway-ingress: "true"`. This
consent gate prevents a Gateway owner from exposing another tenant's Service to
the public internet. Changing a forward's target, target port or protocol, or
removing a forward, drops the established connections of the old target at once;
clients reconnect and land on the new target.

```sh
kubectl label namespace other-ns wgnet.dev/allow-gateway-ingress=true
```

```yaml
  forwards:
    - port: 8080
      protocol: TCP
      service: api
      namespace: other-ns
```

Backend Services of type `ClusterIP` and `NodePort` are supported (both carry a
routable ClusterIP to DNAT to). `ExternalName` Services are rejected in both
traffic policies, and headless Services in `Cluster` mode only, where the DNAT
needs a ClusterIP that `Local` mode never reads; a rejected forward leaves the
Gateway `Ready=False` with reason `UnsupportedServiceType`.

## Operations

### Recreating a gateway VM

The VM's ignition is applied at first boot only, so a change to
`spec.gcp.image` or to anything rendered into user data reaches a running
gateway only by replacing the instance. Delete the composed managed resource
alone:

```sh
kubectl get instances.compute.gcp.m.upbound.io -n <gateway-namespace>
kubectl delete instances.compute.gcp.m.upbound.io -n <gateway-namespace> <instance>
```

The composed resources share the `Gateway`'s namespace; the composite XR carries
the Gateway's own name, so pick the `Instance` by its `crossplane.io/composite`
label if several gateways live there.

The composition rebuilds it in roughly two minutes, during which the tunnel and
every forwarded port are down. `NetworkPolicy` and forward changes need none of
this; they reconcile in place.

With `address.type: Reserved` or `External` the rebuilt instance reattaches the
same address. With `address.type: Ephemeral` it takes a new one, so even this
instance-only rebuild lands on a new public IP and every `dnsHostnames` name has
to re-propagate.

A load-balanced Gateway has no `Instance` to delete; template changes roll out
on their own (see [Load balancing](#load-balancing)). Deleting a member VM by
hand is a permanent deletion: its address is released, it goes `Departing` then
`Departed`, and the MIG creates a replacement.

Do not widen the deletion to force a rebuild. Deleting the `XGatewayGCP`
composite destroys the Address (`address.type: Reserved` only), Firewall,
service account, Secrets, and Instance; an operator-created `Reserved` address is
released, an `External` address stays reserved and unattached, and the VPC
survives. Deleting the last
`Gateway` CR in the cluster additionally tears down the VPC, which is refcounted
across Gateways.

Deleting a `Gateway` unwinds its link first, in both traffic policies: the
operator deletes the link workload and waits for the link pods to exit, then
reaps the leader-election Lease `<gateway>-link`, because a live elector
re-creates a deleted Lease on its next renew. A pod stuck terminating for longer
than its own grace period plus 30s does not hold that teardown up.

### Break-glass SSH

Gateway VMs carry no SSH keys and `block-project-ssh-keys` is set, so access is
OS Login over IAP TCP forwarding. The gateway firewall admits `22` from the IAP
range `35.235.240.0/20` only, targeted at the VM's service account.

```sh
gcloud compute ssh <instance> --zone=<zone> --tunnel-through-iap --project=<project>
```

Authorization is IAM: the caller needs `roles/compute.osLogin` (or
`roles/compute.osAdminLogin` for root) on the project, plus IAP tunnel access.
Revoking the role revokes the shell, with nothing to clean up on the VM.
Setting `operator.enableOsLogin=false` disables OS Login and drops the IAP
firewall rule, leaving no login path at all.

## Development

Run `make test` for the full suite (unit, integration, e2e) or the per-suite
targets `make test-unit` / `make test-integration` / `make test-e2e`.
Composition integration tests dry-run server-side apply for every rendered
composed resource against vendored provider CRDs; `make provider-crds` refreshes
them from the packages pinned in
`k8s/infra/crossplane/crossplane-providers/values.yaml`, and
`make test-integration` fetches the envtest binaries it needs. The e2e suite
self-provisions a kind cluster, the full Crossplane stack, and a real GCP
gateway, so it requires the GCP configuration above. `E2E_MAX_ADDRESSES`
defaults to 8; a fleet counts its members plus one, and a single-instance
Gateway counts one. It must not exceed the region external address quota. Local
development needs [Go](https://go.dev/doc/install),
[kind](https://kind.sigs.k8s.io/docs/user/quick-start/), and a container runtime
— [Docker](https://docs.docker.com/engine/install/) or
[Podman](https://podman.io/docs/installation).

## License

Apache License 2.0. See [LICENSE](LICENSE).
