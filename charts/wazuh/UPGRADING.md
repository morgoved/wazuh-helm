# Upgrading

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

#### Helm 3, removing a protocol

Run the same `helm upgrade` twice. The first one updates the ConfigMap, restarts the workers on
the remaining protocol and drops 514 entirely from the StatefulSet and the Services. The
second one puts back the remaining protocol and restarts the workers again.

#### Downtime

The workers restart in parallel (`podManagementPolicy: Parallel`), so syslog and agent
connections to the workers stop while they come back, once per StatefulSet change: once with
Helm 4 or the Helm 3 path for adding a protocol, twice when removing one with Helm 3. Between
the two upgrades of the removal path, the workers listen on the remaining protocol but no
Service or LoadBalancer port reaches it, so syslog stops until the second upgrade.

#### Do not use `--force` or `--force-replace`

`--force` (Helm 3) and `--force-replace` (Helm 4) replace every object of the release, not just
the ones above. Replacing a bound chart-managed PVC (e.g. the indexer snapshot PVC) fails,
because the rendered PVC has no `spec.volumeName`.
