# Upgrading

## 2.5.0 → 2.5.1

The securityadmin Job is now `<fullname>-indexer-securityadmin` (was `<fullname>-indexer`).
On clusters whose network policy agent derives a pod identity from the pod name prefix (Amazon
VPC CNI), a Job pod `<fullname>-indexer-xxxxx` was matched to the `<fullname>-indexer`
StatefulSet and ran under the indexer's NetworkPolicy, whose egress allows DNS and the cluster
ports only, so the Job could not reach `<fullname>-indexer:9200` and failed. Helm creates the
hook Job under its new name on the next upgrade, but `before-hook-creation` only removes a
previous Job of the *new* name: a failed `<fullname>-indexer` Job left behind by 2.5.0 stays
until you delete it (`kubectl delete job <fullname>-indexer`). The name is capped at 57
characters, with the `-indexer-securityadmin` suffix kept whole, so a long
`indexer.fullnameOverride` cannot push the pod's random suffix past the 63-character limit.

## 2.3.x → 2.4.0

The manager cluster key is no longer rendered into the `<fullname>-manager-config` ConfigMap.
`master.conf` and `worker.conf` now carry `<key>to_be_replaced_by_cluster_key</key>`, and the
official manager image replaces it from the `WAZUH_CLUSTER_KEY` environment variable on every
container start (`set_custom_cluster_key` in its init script). `wazuh.key` keeps working as
before; `wazuh.clusterKey.existingSecret` lets you point `WAZUH_CLUSTER_KEY` at a Secret you
manage, in which case the chart renders no `wazuh-cluster-key` Secret.

- A custom `wazuh.images.repository` whose init script lacks `set_custom_cluster_key` ends up
  with the literal placeholder in `ossec.conf` and the cluster does not form. Every
  `wazuh/wazuh-manager` tag the chart has shipped includes it.
- `wazuh.masterConf` / `wazuh.workerConf` overrides are untouched. They may use the same
  placeholder instead of an inline key.

### Moving an existing release to `wazuh.clusterKey.existingSecret`

Do not point `existingSecret` at `wazuh-cluster-key`, the Secret the chart created. Once
`existingSecret` is set the chart stops rendering that Secret, so Helm removes it from the
release and deletes it while the managers still reference it. Instead:

1. Create a Secret with a different name that holds the current key
   (`kubectl -n <ns> get secret wazuh-cluster-key -o jsonpath='{.data.key}' | base64 -d`).
2. Set `wazuh.clusterKey.existingSecret` to that name and upgrade. The pods switch to the new
   reference and the chart-managed Secret is removed.

With `autoreload.enabled`, a change of `wazuh.key` rolls both manager StatefulSets through a
checksum of the chart-managed Secret. The chart cannot see changes to an external Secret:
after rotating the key there, restart the managers
(`kubectl -n <ns> rollout restart statefulset -l app=<fullname>-manager`).

## 2.1.x → 2.2.0

2.2.0 adds `wazuh.syslog.protocols` (see [Receiving syslog](./README.md#receiving-syslog)).
The default, `[tcp]`, keeps the listener of 2.1.x, but the objects around it change.

### Changed defaults

- The LoadBalancer used to always expose 514/UDP, which nothing listened on unless you added
  a udp `<remote>` through `wazuh.worker.extraConf`. Syslog ports now follow
  `wazuh.loadBalancer.ports`: the default (`registration`, `agents-events`) leaves them out.
  Add `syslog-tcp` and/or `syslog-udp` to keep syslog on the LoadBalancer. They target the
  workers' named ports, so the master is no longer a syslog endpoint, and no syslog port is
  added when `wazuh.worker.enabled` is false.
- The worker NetworkPolicy used to allow both 514/TCP and 514/UDP. It now only allows the
  listed protocols, so add `udp` to `wazuh.syslog.protocols` if your devices send over UDP.
- The syslog Service ports are renamed from `syslog` to `syslog-tcp`/`syslog-udp`.
- If you added a udp `<remote>` through `wazuh.worker.extraConf`, remove it when you add `udp`
  to `wazuh.syslog.protocols`, otherwise remoted gets two listeners on udp/514.

### Adding or removing a protocol on an existing release

Helm's client-side apply (the default for Helm 3, and for Helm 4 releases first installed
client-side) merges Service ports on `port` and container ports on `containerPort` alone. An
upgrade that adds or removes a protocol while the other one stays on 514 then drops ports from
the worker StatefulSet, the worker Service and the LoadBalancer, and a Service whose named
`targetPort` is gone from the pods loses its endpoints: `[tcp]` → `[udp, tcp]` loses TCP,
`[udp, tcp]` → `[tcp]` loses 514 entirely.

Not affected: fresh installs, the upgrade from 2.1.x that keeps a single protocol (the
default), and switching between `[tcp]` and `[udp]`. Run those upgrades as usual.

The workers copy `worker.conf` from the manager ConfigMap when they start, so the steps below
make sure they restart after the ConfigMap holds the new listeners.

#### Helm 4

Run the upgrade server-side:

```bash
helm upgrade wazuh wazuh/wazuh -n wazuh --version 2.2.0 -f values.yaml \
  --server-side=true --force-conflicts
```

Helm applies the ConfigMap before the StatefulSet, and the workers restart once. Later
upgrades can stay server-side.

#### Helm 3, adding a protocol

Apply the manager ConfigMap server-side first, then the objects whose ports change, then run
the upgrade with the same values. Run it as a script, so that it stops if a step fails instead
of going on with a plain upgrade:

```bash
#!/usr/bin/env bash
set -euo pipefail
render() { helm template wazuh wazuh/wazuh -n wazuh --version 2.2.0 -f values.yaml "$@"; }
apply() { kubectl -n wazuh apply --server-side --force-conflicts --field-manager=syslog-protocols -f -; }

# 1. The new worker.conf, before any worker restarts.
render --show-only templates/manager/configmap.yaml | apply
# 2. The objects whose ports change. This restarts the workers.
render \
  --show-only templates/manager/worker/statefulset.yaml \
  --show-only templates/manager/worker/service.yaml \
  --show-only templates/manager/worker/networkpolicy.yaml \
  --show-only templates/manager/load-balancer.yaml \
  | apply
# 3. The upgrade itself.
helm upgrade wazuh wazuh/wazuh -n wazuh --version 2.2.0 -f values.yaml
```

`helm template --show-only` fails on a template that renders nothing, so leave out
`networkpolicy.yaml` when `wazuh.worker.networkPolicy.enabled` is false, and
`load-balancer.yaml` when `wazuh.loadBalancer.enabled` is false.

The worker NetworkPolicy and the LoadBalancer must already belong to the release. If you want
to enable either of them as well, do it in a separate `helm upgrade` first, keeping the
current `wazuh.syslog.protocols`. Otherwise `kubectl apply` creates it without Helm's ownership
metadata, and the `helm upgrade` that follows fails because the object already exists.

#### Helm 3, removing a protocol

Run the same `helm upgrade` twice. The first one updates the ConfigMap, restarts the workers on
the remaining protocol and drops 514 entirely from the StatefulSet and the Services. The
second one puts back the remaining protocol and restarts the workers again.

#### Downtime

Each StatefulSet change rolls the workers, one at a time with the default `RollingUpdate`
strategy: once with Helm 4 or the Helm 3 path for adding a protocol, twice when removing one
with Helm 3. The syslog and agent connections of each worker are interrupted while it
restarts, and with a single worker syslog stops until it is back. Between the two upgrades of
the Helm 3 removal path, the workers listen on the remaining protocol but no Service or
LoadBalancer port reaches it, so syslog stops until the second upgrade.

#### Do not use `--force` or `--force-replace`

`--force` (Helm 3) and `--force-replace` (Helm 4) replace every object of the release, not just
the ones above. Replacing a bound chart-managed PVC (e.g. the indexer snapshot PVC) fails,
because the rendered PVC has no `spec.volumeName`.

## Changing the API certificate issuer or the Gateway's CA

`wazuh.api.certificate` and `wazuh.api.gateway.backendTLS` move independently of the managers:
cert-manager rewrites the `api-tls` Secret when the issuer changes, but a manager only loads the
file on its next start, and the Gateway trusts whatever `backendTLS` says the moment the
`BackendTLSPolicy` is applied. `autoreload.enabled` does not help here: a checksum of the
Certificate manifest would roll the managers before cert-manager has issued the new certificate.
The `BackendTLSPolicy` always validates the Gateway host, which is a SAN in every mode, so only
the trusted CA has to be staged. In all sequences, "wait for the certificate" means

```sh
kubectl -n <ns> wait certificate <fullname>-api --for=condition=Ready --timeout=10m
```

and "restart the managers" means both StatefulSets, and not continuing while either fails:

```sh
kubectl -n <ns> rollout restart statefulset/<fullname>-manager-master statefulset/<fullname>-manager-worker
kubectl -n <ns> rollout status statefulset/<fullname>-manager-master --timeout=10m
kubectl -n <ns> rollout status statefulset/<fullname>-manager-worker --timeout=10m
```

Agents reconnect on their own after a restart.

### Rotating a private CA (`caCertificateRef` stays)

No downtime: the ConfigMap holds both CAs while the managers switch.

1. Add the new CA to the ConfigMap's `ca.crt` (PEM bundle, old CA first or last, order is free).
2. Change `wazuh.api.certificate.issuerRef` and upgrade. Wait for the certificate. The Gateway
   still validates the old certificate against the bundle.
3. Restart the managers. They now serve the new certificate, trusted through the bundle.
4. Remove the old CA from the bundle.

### Private CA → public issuer (`wellKnownCACertificates: System`)

1. Optional, to avoid downtime: add the public CA's root (for example ISRG Root X1 for Let's
   Encrypt) to the ConfigMap bundle.
2. Change `wazuh.api.certificate.issuerRef` and set `wazuh.api.certificate.serviceNames: false`
   (a public CA only issues public names); keep `caCertificateRef` for now. Upgrade and wait for
   the certificate. Nothing has changed for the Gateway yet: the managers serve the old
   certificate, which carries the Gateway host, trusted through the bundle.
3. Restart the managers. Downtime starts here if step 1 was skipped: the Gateway rejects the new
   certificate, whose CA is not in the bundle.
4. Set `wazuh.api.gateway.backendTLS.wellKnownCACertificates: System` (and clear
   `caCertificateRef.name`) and upgrade. The policy applies at once; downtime, if any, ends here.
   The ConfigMap is no longer referenced.

### Public issuer → private CA

1. Create the ConfigMap. To avoid downtime, include the public CA's root next to the private CA.
2. Set `wazuh.api.gateway.backendTLS.caCertificateRef.name` to it and clear
   `wellKnownCACertificates`; upgrade. Downtime starts here if the public root was left out: the
   Gateway no longer trusts the certificate the managers serve.
3. Change `wazuh.api.certificate.issuerRef` (and `serviceNames: true` if in-cluster clients
   should verify the certificate too); upgrade and wait for the certificate.
4. Restart the managers. Downtime, if any, ends here.
5. Remove the public root from the bundle.

Renewals by cert-manager need no steps: the same CA signs the renewed certificate, and the
managers load it on their next restart (`certificates.renewBefore` leaves ample time).
