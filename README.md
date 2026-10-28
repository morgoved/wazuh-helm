# wazuh-kubernetes-helm-chart

![Version: 2.2.0](https://img.shields.io/badge/Version-2.2.0-informational?style=flat-square)
![AppVersion: 4.14.9](https://img.shields.io/badge/AppVersion-4.14.9-informational?style=flat-square)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/wazuh-helm-morgoved)](https://artifacthub.io/packages/search?repo=wazuh-helm-morgoved)

Wazuh is a centralized Security Information and Event Management (SIEM) platform offering vulnerability intelligence and threat monitoring capabilities.

### Generating Certificates

To generate the necessary certificates, refer to the instructions available [here](https://github.com/wazuh/wazuh-kubernetes/blob/master/instructions.md).

### Retrieving Hashes

To retrieve hashes, execute the following command:

```bash
docker run --rm -ti wazuh/wazuh-indexer:4.14.9 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh`
```

### Automatic Configuration Updates

Any changes made to the indexer configuration or secrets will be automatically applied via job hooks. The [`reloader`](https://artifacthub.io/packages/helm/cloudnativeapp/reloader) monitors for updates to ensure seamless application of changes. For a practical example of a production configuration, check the example folder.

### Compatibility

This Helm chart has been tested with Wazuh version 4.14.9. Please note:

Wazuh supports only a single master node and multiple worker nodes. Although the configuration is prepared for a multi-master setup, Wazuh does not currently support this feature.
All XML configuration files are automatically updated through init containers.

### Gateway API support

As an alternative to `dashboard.ingress`, the dashboard can be exposed through the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) via `dashboard.gateway.enabled`. This requires:

- The Gateway API CRDs installed on the cluster, Gateway API v1.5+ (`BackendTLSPolicy` and `ListenerSet` are GA as of v1.5).
- A Gateway controller that supports `BackendTLSPolicy` if `dashboard.enable_ssl` is set, and a pre-existing `Gateway` resource referenced by `dashboard.gateway.parentRef`.

By default the chart creates a dedicated `ListenerSet` (`dashboard.gateway.listenerSet.enabled: true`) attached to that `Gateway`, and attaches the dashboard `HTTPRoute` to the `ListenerSet`. This requires the selected Gateway controller to support `ListenerSet`s and the parent `Gateway` to allow them via `spec.allowedListeners` — not every controller does. Set `dashboard.gateway.listenerSet.enabled: false` to attach the `HTTPRoute` directly to the `Gateway` instead; in that case the `Gateway`'s own listener for the dashboard hostname must already exist.

Edge TLS (client to Gateway) and backend TLS (Gateway to the dashboard Service) are configured independently:

- `dashboard.gateway.tls.*` controls edge TLS. By default the chart creates a cert-manager `Certificate` for it; set `dashboard.gateway.tls.certificate.create: false` and `dashboard.gateway.tls.secretName` to reuse an existing Secret instead.
- `dashboard.gateway.backendTLS.caCertificateRef.name` is required when both `dashboard.gateway.enabled` and `dashboard.enable_ssl` are true. It must name an existing `ConfigMap` (key `ca.crt`) trusted to validate the dashboard's own TLS certificate — this is decoupled from the chart's internal `dashboard-tls` Secret so any CA distribution mechanism (e.g. `trust-manager`) can be used.

### Syslog

The workers receive syslog on port 514 over the transports listed in `wazuh.syslog.protocols` (`tcp` by default, `udp` or both). The listener, the worker Service and NetworkPolicy, and the LoadBalancer (when `wazuh.loadBalancer.ports` lists `syslog-tcp`/`syslog-udp`, or is empty) all follow that list. `wazuh.syslog.networkPolicyFrom` restricts which sources the worker NetworkPolicy lets reach 514 (any by default). See [Receiving syslog](./charts/wazuh/README.md#receiving-syslog) for the upgrade notes from 2.1.x, including the Helm flags needed when adding or removing a protocol on an existing release.

### Contributing

This fork welcomes contributions and is open to transitioning into the official Wazuh project repository. Contributions are encouraged and appreciated.

`charts/wazuh/values.schema.json` is generated from `charts/wazuh/values.yaml` with the
[helm-values-schema-json](https://github.com/losisin/helm-values-schema-json) plugin: after changing
`values.yaml`, run `helm schema` from the repository root (or let the pre-commit hook do it). Unknown
keys are rejected by default; annotate free-form Kubernetes objects with
`# @schema additionalProperties: true; skipProperties: true` and nullable values with
`# @schema type: [string, null]`. `charts/wazuh/tests/schema_test.sh` checks that the schema is up to
date and that every `.Values` path used by the templates is declared in `values.yaml`.

## Values

To see all values and instructions, refer to the [README.md](./charts/wazuh/README.md) of the chart.
