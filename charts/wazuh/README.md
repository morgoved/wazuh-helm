# wazuh

![Version: 1.0.14](https://img.shields.io/badge/Version-1.0.14-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 4.14.1](https://img.shields.io/badge/AppVersion-4.14.1-informational?style=flat-square)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/wazuh-helm-morgoved)](https://artifacthub.io/packages/search?repo=wazuh-helm-morgoved)
## Introduction

Wazuh is a free and open source security platform that unifies XDR and SIEM protection for endpoints and cloud workloads.

**Homepage:** <https://wazuh.com/>

## Maintainers

| Name      | Email                            | Url                            |
| --------- | -------------------------------- | ------------------------------ |
| Morgoved  | <morgyes@gmail.com>              | <https://github.com/morgoved>  |
| Kaslie    | <jinyi_lie@yahoo.com>            | <https://github.com/Kaslie>    |
| ShorMario |                                  | <https://github.com/ShorMario> |
| Dani      | <andre.gomes@promptlyhealth.com> | <https://github.com/Ca-moes>   |
| TrueDru   |                                  | <https://github.com/TrueDru>   |
| 71g3pf4c3 |                                  | <https://github.com/71g3pf4c3> |

## Source Code

- <https://github.com/morgoved/wazuh-helm>

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8.0+
- PV provisioner support in the underlying infrastructure

## Get Helm Repository Info

```shell
helm repo add wazuh-helm https://morgoved.github.io/wazuh-helm/
helm repo update
```

## Install Helm Chart

```shell
helm install [RELEASE_NAME] wazuh-helm/wazuh
```

### Installation with changing credentials

> NOTE!
> Currently changing the parameters still involve manual password hashing, as the hash has to be entered in the internal_users.yml of wazuh.
> The current implementation should only be a temporary solution, as the helm engine might get the ability to create bcrypt hashes with setting rounds / costs as part of the already existing bcrypt function.

When changing `indexer.cred.password` you also have to adjust `indexer.cred.passwordHash` in order to get the correct value, you have to hash the password with bcrypt and 12 rounds / costs. You can do so via CLI or some online converter in the web.

Same applies when changing `dashboard.cred.password`

## Parameters

### cert-manager This are the parameters for the official sub-chart for cert-manager, here you

| Name                   | Description                                              | Value   |
| ---------------------- | -------------------------------------------------------- | ------- |
| `cert-manager.enabled` | this enabled or disables the sub-chart getting deployed. | `false` |

### certificates If cert-manager is present, the certificates can be generated automatically.

| Name                                 | Description                                                      | Value        |
|--------------------------------------|------------------------------------------------------------------|--------------|
| `certificates.requestPolicy.enabled` | RequestPolicy for the certificates.                              | `false`      |
| `certificates.issuer.name`           | of the issuer used for signing the certificates. If this is null | `nil`        |
| `certificates.issuer.type`           | defines the type of the issuer, possible values are issuer and   | `issuer`     |
| `certificates.duration`              | timeframe for validity of cert.                                  | `2160h`      |
| `certificates.renewBefore`           | timeframe before the cert gets renewed.                          | `360h`       |
| `certificates.subject.organization`  | Organization for the internal certificate.                       | `Company`    |
| `certificates.subject.country`       | Country for the internal certificate.                            | `US`         |
| `certificates.subject.locality`      | Locality for the internal certificate.                           | `California` |

### indexer configuration of the wazuh indexer.

| Name                                         | Description                                                                    | Value                                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| `externalIndexer.enabled`                    | defines if we use external indexer or not                                      | `false`                                                        |
| `externalIndexer.host`                       | defines external indexer host and scheme                                       | `https://wazuh-indexer.example.com`                            |
| `externalIndexer.port`                       | defines external indexer port                                                  | `9200`                                                         |
| `indexer.enabled`                            | defines if we deploy indexer or not                                            | `true`                                                         |
| `indexer.replicas`                           | number of replicas used in statefulset.                                        | `3`                                                            |
| `indexer.annotations`                        | additional annotations set on statefulset.                                     | `{}`                                                           |
| `indexer.updateStrategy`                     | updateStrategy for the statefulset.                                            | `RollingUpdate`                                                |
| `indexer.images.repository`                  | name of the image used. If you use your own image registry                     | `wazuh/wazuh-indexer`                                          |
| `indexer.images.tag`                         | Tag of the image.                                                              | `4.14.1`                                                       |
| `indexer.images.pullPolicy`                  | pullPolicy of the image.                                                       | `IfNotPresent`                                                 |
| `indexer.resources.requests.cpu`             | Minimum CPU assigned to the pod.                                               | `500m`                                                         |
| `indexer.resources.requests.memory`          | Minimum memory assigned to the pod.                                            | `1Gi`                                                          |
| `indexer.resources.limits.cpu`               | Maximum CPU used by the pod.                                                   | `1000m`                                                        |
| `indexer.resources.limits.memory`            | Maximum memory used by the pod.                                                | `2Gi`                                                          |
| `indexer.pdb.enabled`                        | Enables pdb for indexer.                                                       | `true`                                                         |
| `indexer.livenessProbe.periodSeconds`        | How often to perform the probe.                                                | `20`                                                           |
| `indexer.livenessProbe.timeoutSeconds`       | When the probe times out.                                                      | `5`                                                            |
| `indexer.livenessProbe.failureThreshold`     | Minimum failures for the probe to be considered failed after having succeeded. | `10`                                                           |
| `indexer.livenessProbe.successThreshold`     | Minimum successes for the probe to be considered successful                    | `1`                                                            |
| `indexer.livenessProbe.initialDelaySeconds`  | Delay before liveness probe is initiated.                                      | `10`                                                           |
| `indexer.readinessProbe.periodSeconds`       | How often to perform the probe.                                                | `20`                                                           |
| `indexer.readinessProbe.timeoutSeconds`      | When the probe times out.                                                      | `5`                                                            |
| `indexer.readinessProbe.failureThreshold`    | Minimum failures for the probe to be considered failed after having succeeded. | `10`                                                           |
| `indexer.readinessProbe.successThreshold`    | Minimum successes for the probe to be considered successful                    | `1`                                                            |
| `indexer.readinessProbe.initialDelaySeconds` | Delay before liveness probe is initiated.                                      | `10`                                                           |
| `indexer.securityContext.fsGroup`            | Set the pods Security Context fsGroup.                                         | `1000`                                                         |
| `indexer.networkPolicy.enabled`              | Specifies whether a NetworkPolicy should be created.                           | `true`                                                         |
| `indexer.service.type`                       | Type of the created service.                                                   | `ClusterIP`                                                    |
| `indexer.service.annotations`                | Annotations of the created service.                                            | `{}`                                                           |
| `indexer.service.httpPort`                   | Port for the http endpoint.                                                    | `9200`                                                         |
| `indexer.service.nodes`                      | Port for the nodes endpoint.                                                   | `9300`                                                         |
| `indexer.service.metrics`                    | Port for the metrics endpoint.                                                 | `9600`                                                         |
| `indexer.nodeSelector`                       |                                                                                | `{}`                                                           |
| `indexer.additionalEnv`                      | Possibility to define additional env vars in the pod.                          | `[]`                                                           |
| `indexer.config.opensearch`                  | Configuration of opensearch.yml.                                               | `{{ include "wazuh.indexer.opensearchConfig" . }}`             |
| `indexer.config.internalUsers`               | Configuration of internalUsers of the indexer.                                 | `{{ include "wazuh.indexer.internalUsers" . }}`                |
| `indexer.config.securityConfig`              | Configuration of securityConfig of the indexer.                                | `{{ include "wazuh.indexer.securityConfig" . }}`               |
| `indexer.config.rolesMapping`                | Configuration of rolesMapping of the indexer.                                  | `{{ include "wazuh.indexer.rolesMapping" . }}`                 |
| `indexer.config.roles`                       | Configuration of roles of the indexer.                                         | `{{ include "wazuh.indexer.roles" . }}`                        |
| `indexer.sysctlImage.enabled`                | Enable kernel settings modifier image                                          | `false`                                                        |
| `indexer.sysctlImage.images.repository`      | name of the image used. If you use your own image registry                     | `bitnamilegacy/os-shell`                                             |
| `indexer.sysctlImage.images.tag`             | Tag of the image.                                                              | `12-debian-12-r43`                                             |
| `indexer.storageSize`                        | Defines the size of the pvc used by the statefulset.                           | `50Gi`                                                         |
| `indexer.storageClass`                       | Defines the storageClass of the pvc used by the statefulset.                   | `nil`                                                          |
| `indexer.cred.existingSecret`                | Name of the existingSecret which holds the key "INDEXER_PASSWORD".             | `""`                                                           |
| `indexer.cred.password`                      | Value of the password for the admin user.                                      | `WazuhSecretPassword`                                          |
| `indexer.cred.passwordHash`                  | Hash of the password for the admin user. To create this, follow the README.    | `$2a$12$zGWIT7wkPKT/zww3bmMyp.KuWXH4RzgxiB91Q8NGFcqpyPy.R2Rcq` |
| `indexer.dnsPolicy`                          | DNS policy for the pod.                                                        | `""`                                                           |
| `indexer.dnsConfig`                          | DNS configuration for the pod.                                                 | `{}`                                                           |

### indexer configuration of the wazuh dashboard. Kibana for elasticsearch with Wazuh plugins

| Name                                           | Description                                                                        | Value                                                          |
| ---------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `dashboard.replicas`                           | number of replicas used in deployment.                                             | `1`                                                            |
| `dashboard.annotations`                        | additional annotations set on deployment.                                          | `{}`                                                           |
| `dashboard.images.repository`                  | name of the image used. If you use your own image registry                         | `wazuh/wazuh-dashboard`                                        |
| `dashboard.images.tag`                         | Tag of the image.                                                                  | `4.14.1`                                                       |
| `dashboard.images.pullPolicy`                  | pullPolicy of the image.                                                           | `IfNotPresent`                                                 |
| `dashboard.images.updateStrategy`              | updateStrategy of the image.                                                       | `OnDelete`                                                     |
| `dashboard.resources.requests.cpu`             | Minimum CPU assigned to the pod.                                                   | `500m`                                                         |
| `dashboard.resources.requests.memory`          | Minimum memory assigned to the pod.                                                | `512Mi`                                                        |
| `dashboard.resources.limits.cpu`               | Maximum CPU used by the pod.                                                       | `1000m`                                                        |
| `dashboard.resources.limits.memory`            | Maximum memory used by the pod.                                                    | `1Gi`                                                          |
| `dashboard.pdb.enabled`                        | Enables pdb for dashboard.                                                         | `false`                                                        |
| `dashboard.livenessProbe.periodSeconds`        | How often to perform the probe.                                                    | `20`                                                           |
| `dashboard.livenessProbe.timeoutSeconds`       | When the probe times out.                                                          | `5`                                                            |
| `dashboard.livenessProbe.failureThreshold`     | Minimum failures for the probe to be considered failed after having succeeded.     | `10`                                                           |
| `dashboard.livenessProbe.successThreshold`     | Minimum successes for the probe to be considered successful                        | `1`                                                            |
| `dashboard.livenessProbe.initialDelaySeconds`  | Delay before liveness probe is initiated.                                          | `10`                                                           |
| `dashboard.readinessProbe.periodSeconds`       | How often to perform the probe.                                                    | `20`                                                           |
| `dashboard.readinessProbe.timeoutSeconds`      | When the probe times out.                                                          | `5`                                                            |
| `dashboard.readinessProbe.failureThreshold`    | Minimum failures for the probe to be considered failed after having succeeded.     | `10`                                                           |
| `dashboard.readinessProbe.successThreshold`    | Minimum successes for the probe to be considered successful                        | `1`                                                            |
| `dashboard.readinessProbe.initialDelaySeconds` | Delay before liveness probe is initiated.                                          | `10`                                                           |
| `dashboard.securityContext`                    | Parameter to configure the securityContext of the pod.                             | `{}`                                                           |
| `dashboard.networkPolicy.enabled`              | Specifies whether a NetworkPolicy should be created.                               | `true`                                                         |
| `dashboard.service.type`                       | Type of the created service.                                                       | `ClusterIP`                                                    |
| `dashboard.service.annotations`                | Annotations of the created service.                                                | `{}`                                                           |
| `dashboard.service.httpPort`                   | Port for the http endpoint.                                                        | `5601`                                                         |
| `dashboard.nodeSelector`                       |                                                                                    | `{}`                                                           |
| `dashboard.additionalEnv`                      | Possibility to define additional env vars in the pod.                              | `[]`                                                           |
| `dashboard.enable_ssl`                         | with this you will be able to access kibana on http port instead of                | `false`                                                        |
| `dashboard.config`                             | Configuration of the dashboard parameters, this should not be changed.             | `{{ include "wazuh.dashboard.config" . }}
`                    |
| `dashboard.cred.existingSecret`                | Name of the existingSecret which holds the key "DASHBOARD_PASSWORD".               | `""`                                                           |
| `dashboard.cred.username`                      | Value of the username for the kibanaserver user.                                   | `kibanaserver`                                                 |
| `dashboard.cred.password`                      | Value of the password for the kibanaserver user.                                   | `kibanaserver`                                                 |
| `dashboard.cred.passwordHash`                  | Hash of the password for the kibanaserver user. To create this, follow the README. | `$2a$12$7NCZ.l9ntPhou5zNjZIU4uqXNNWMF7SyF6Y6mcjhHTB6Z1eQubHC.` |
| `dashboard.ingress.enabled`                    | Enable ingress record generation for dashboard.                                    | `false`                                                        |
| `dashboard.ingress.className`                  | Defines the ingress class name used.                                               | `""`                                                           |
| `dashboard.ingress.tls`                        | Allows to use specific tls certificate.                                            | `[]`                                                           |
| `dashboard.ingress.annotations`                | Used for detailed configuration.                                                   | `{}`                                                           |
| `dashboard.ingress.host`                       | Defines the hostname and URL under which the dashboard gets                        | `wazuh.example.com`                                            |
| `dashboard.dnsPolicy`                          | DNS policy for the pod.                                                            | `""`                                                           |
| `dashboard.dnsConfig`                          | DNS configuration for the pod.                                                     | `{}`                                                           |

### wazuh configuration of the wazuh core component.

| Name                                            | Description                                                                       | Value                                      |
| ----------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------ |
| `wazuh.syslog_enable`                           | Enables the syslog of the wazuh instance.                                         | `true`                                     |
| `wazuh.key`                                     | Defines the key of the wazuh cluster.                                             | `c98b62a9b6169ac5f67dae55ae4a9088`         |
| `wazuh.images.repository`                       | name of the image used. If you use your own image registry                        | `wazuh/wazuh-manager`                      |
| `wazuh.images.tag`                              | Tag of the image.                                                                 | `4.14.1`                                   |
| `wazuh.images.pullPolicy`                       | pullPolicy of the image.                                                          | `IfNotPresent`                             |
| `wazuh.service.annotations`                     | Annotations of the created service.                                               | `{}`                                       |
| `wazuh.service.port`                            | Port for the http endpoint.                                                       | `1516`                                     |
| `wazuh.nodeSelector`                            |                                                                                   | `{}`                                       |
| `wazuh.apiCred.existingSecret`                  | name of the existingSecret in the namespace. Expected keys are 'API_USERNAME' and | `""`                                       |
| `wazuh.apiCred.username`                        | name of the username.                                                             | `wazuh-wui`                                |
| `wazuh.apiCred.password`                        | password of the user. Note that the password must have a length                   | `MyS3cr37P450r.*-`                         |
| `wazuh.authd.existingSecret`                    | name of the existingSecret in the namespace.                                      | `""`                                       |
| `wazuh.authd.pass`                              | password of the authd.                                                            | `password`                                 |
| `wazuh.initContainer.image`                     | Image used by the update-index container                                          | `alpine`                                   |
| `wazuh.initContainer.resources.requests.cpu`    | Minimum CPU assigned to the pod.                                                  | `250m`                                     |
| `wazuh.initContainer.resources.requests.memory` | Minimum memory assigned to the pod.                                               | `512Mi`                                    |
| `wazuh.initContainer.resources.limits.cpu`      | Maximum CPU used by the pod.                                                      | `1000m`                                    |
| `wazuh.initContainer.resources.limits.memory`   | Maximum memory used by the pod.                                                   | `1Gi`                                      |
| `wazuh.localDecoder`                            | Configuration of the local decoder.                                               | `{{ include "wazuh.localDecoder" . }}
`    |
| `wazuh.localRules`                              | Configuration of the local rules.                                                 | `{{ include "wazuh.localRules" . }}
`      |
| `wazuh.internalOptions`                         | Configuration of the internal option.                                             | `{{ include "wazuh.internalOptions" . }}
` |

### wazuh.master configuration of the wazuh master component.

| Name                                               | Description                                                  | Value                                  |
| -------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------- |
| `wazuh.master.annotations`                         | additional annotations set on statefulset.                   | `{}`                                   |
| `wazuh.master.resources.requests.cpu`              | Minimum CPU assigned to the pod.                             | `500m`                                 |
| `wazuh.master.resources.requests.memory`           | Minimum memory assigned to the pod.                          | `512Mi`                                |
| `wazuh.master.resources.limits.cpu`                | Maximum CPU used by the pod.                                 | `1000m`                                |
| `wazuh.master.resources.limits.memory`             | Maximum memory used by the pod.                              | `1Gi`                                  |
| `wazuh.master.service.type`                        | Type of the created service.                                 | `ClusterIP`                            |
| `wazuh.master.service.annotations`                 | Annotations of the created service.                          | `{}`                                   |
| `wazuh.master.service.ports`                       | Add Ports for the endpoints.                                 | ``.                                    |
| `wazuh.master.livenessProbe`                       | Parameter to configure the livenessProbe.                    | `{}`                                   |
| `wazuh.master.readinessProbe`                      | Parameter to configure the readinessProbe.                   | `{}`                                   |
| `wazuh.master.securityContext.capabilities.add`    | Additional capabilities.                                     | `["SYS_CHROOT"]`                       |
| `wazuh.master.additionalEnv`                       | Possibility to define additional env vars in the pod.        | `[]`                                   |
| `wazuh.master.additionalVolumes`                   | Possibility to define additional volumes in the pod.         | `[]`                                   |
| `wazuh.master.additionalVolumeMounts`              | Possibility to define additional volumeMounts in the pod.    | `[]`                                   |
| `wazuh.master.networkPolicy.enabled`               | Specifies whether a NetworkPolicy should be created.         | `true`                                 |
| `wazuh.master.storageSize`                         | Defines the size of the pvc used by the statefulset.         | `50Gi`                                 |
| `wazuh.master.storageClass`                        | Defines the storageClass of the pvc used by the statefulset. | `nil`                                  |
| `wazuh.master.conf`                                | Config for the wazuh master, do not change!                  | `{{ include "wazuh.master.conf" . }}`  |
| `wazuh.master.extraConf`                           | Gets appended to the wazuh.master.conf.                      | `""`                                   |
| `wazuh.master.dnsPolicy`                           | DNS policy for the pod.                                      | `""`                                   |
| `wazuh.master.dnsConfig`                           | DNS configuration for the pod.                               | `{}`                                   |

### wazuh.worker configuration of the wazuh worker component.

| Name                                              | Description                                                  | Value                                  |
| ------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------- |
| `wazuh.worker.replicas`                           | number of replicas used in statefulset.                      | `2`                                    |
| `wazuh.worker.annotations`                        | additional annotations set on deployment.                    | `{}`                                   |
| `wazuh.worker.resources.requests.cpu`             | Minimum CPU assigned to the pod.                             | `500m`                                 |
| `wazuh.worker.resources.requests.memory`          | Minimum memory assigned to the pod.                          | `512Mi`                                |
| `wazuh.worker.resources.limits.cpu`               | Maximum CPU used by the pod.                                 | `1000m`                                |
| `wazuh.worker.resources.limits.memory`            | Maximum memory used by the pod.                              | `1Gi`                                  |
| `wazuh.worker.service.type`                       | Type of the created service.                                 | `ClusterIP`                            |
| `wazuh.worker.service.annotations`                | Annotations of the created service.                          | `{}`                                   |
| `wazuh.worker.service.ports`                      | Add Ports for the endpoints.                                 | ``.                                    |
| `wazuh.worker.pdb.enabled`                        | Enables pdb for worker.                                      | `true`                                 |
| `wazuh.worker.livenessProbe`                      | Parameter to configure the livenessProbe.                    | `{}`                                   |
| `wazuh.worker.readinessProbe`                     | Parameter to configure the readinessProbe.                   | `{}`                                   |
| `wazuh.worker.securityContext.capabilities.add`   | Additional capabilities.                                     | `["SYS_CHROOT"]`                       |
| `wazuh.worker.additionalEnv`                      | Possibility to define additional env vars in the pod.        | `[]`                                   |
| `wazuh.worker.additionalVolumes`                  | Possibility to define additional volumes in the pod.         | `[]`                                   |
| `wazuh.worker.additionalVolumeMounts`             | Possibility to define additional volumeMounts in the pod.    | `[]`                                   |
| `wazuh.worker.networkPolicy.enabled`              | Specifies whether a NetworkPolicy should be created.         | `true`                                 |
| `wazuh.worker.storageSize`                        | Defines the size of the pvc used by the statefulset.         | `50Gi`                                 |
| `wazuh.worker.storageClass`                       | Defines the storageClass of the pvc used by the statefulset. | `nil`                                  |
| `wazuh.worker.conf`                               | Config for the wazuh worker, do not change!                  | `{{ include "wazuh.worker.conf" . }}`  |
| `wazuh.worker.extraConf`                          | Gets appended to the wazuh.worker.conf.                      | `""`                                   |
| `wazuh.worker.dnsPolicy`                          | DNS policy for the pod.                                      | `""`                                   |
| `wazuh.worker.dnsConfig`                          | DNS configuration for the pod.                               | `{}`                                   |

### agent configuration of the wazuh agent component.

| Name                                              | Description                                                  | Value                                  |
| ------------------------------------------------- | ------------------------------------------------------------ | -------------------------------------- |
| `agent.enabled`                                   | Enable the agent.                                            | `false`                                |
| `agent.service.port`                              | Port for the service.                                        | `5000`                                 |
| `agent.service.type`                              | Type of the created service.                                 | `ClusterIP`                            |
| `agent.service.annotations`                       | Annotations of the created service.                          | `{}`                                   |
| `agent.labels`                                    | Extra labels for the agent.                                  | `{}`                                   |
| `agent.dnsPolicy`                                 | DNS policy for the pod.                                      | `""`                                   |
| `agent.dnsConfig`                                 | DNS configuration for the pod.                               | `{}`                                   |
