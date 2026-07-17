# wazuh

![Version: 2.0.1](https://img.shields.io/badge/Version-2.0.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 4.14.3](https://img.shields.io/badge/AppVersion-4.14.3-informational?style=flat-square)
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

### global These parameters control the global networking behavior across all services.

| Name                              | Description                                        | Value   |
| --------------------------------- | -------------------------------------------------- | ------- |
| `global.dualStack.enabled`        | Enables dual-stack networking logic globally.      | `false` |
| `global.dualStack.ipFamilyPolicy` | Sets the IP family policy for Kubernetes Services. | `""`    |
| `global.dualStack.ipFamilies`     | A list defining the order of IP families.          | `[]`    |

### cert-manager This are the parameters for the official sub-chart for cert-manager, here you

| Name                   | Description                                              | Value   |
| ---------------------- | -------------------------------------------------------- | ------- |
| `cert-manager.enabled` | this enabled or disables the sub-chart getting deployed. | `false` |

### certificates If cert-manager is present, the certificates can be generated automatically.

| Name                                 | Description                                                                  | Value        |
| ------------------------------------ | ---------------------------------------------------------------------------- | ------------ |
| `certificates.enabled`               | deploy all certificates and issuer configuration with certmanager if enabled | `true`       |
| `certificates.requestPolicy.enabled` | Enable CertificateRequestPolicy                                              | `false`      |
| `certificates.issuer.name`           | of the issuer used for signing the certificates. If this is null             | `nil`        |
| `certificates.issuer.type`           | defines the type of the issuer, possible values are issuer and               | `issuer`     |
| `certificates.duration`              | timeframe for validity of cert.                                              | `2160h`      |
| `certificates.renewBefore`           | timeframe before the cert gets renewed.                                      | `360h`       |
| `certificates.subject.organization`  | Organization for the internal certificate.                                   | `Company`    |
| `certificates.subject.country`       | Country for the internal certificate.                                        | `US`         |
| `certificates.subject.locality`      | Locality for the internal certificate.                                       | `California` |

### externalIndexer configuration of the wazuh indexer.

| Name                      | Description                               | Value                               |
| ------------------------- | ----------------------------------------- | ----------------------------------- |
| `externalIndexer.enabled` | defines if we use external indexer or not | `false`                             |
| `externalIndexer.host`    | defines external indexer address          | `https://wazuh-indexer.example.com` |
| `externalIndexer.port`    | defines external indexer port             | `9200`                              |

### indexer configuration of the wazuh indexer.

| Name                                         | Description                                                                                | Value                                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| `indexer.enabled`                            | defines if we deploy indexer or not                                                        | `true`                                                         |
| `indexer.serviceAccount.create`              | Create service account for indexer                                                         | `false`                                                        |
| `indexer.serviceAccount.annotations`         | Annotations for indexer service account                                                    | `{}`                                                           |
| `indexer.serviceAccount.name`                | Name of the indexer service account                                                        | `wazuh-indexer`                                                |
| `indexer.replicas`                           | number of replicas used in statefulset.                                                    | `3`                                                            |
| `indexer.annotations`                        | additional annotations set on statefulset.                                                 | `{}`                                                           |
| `indexer.extraPodLabels`                     | Extra labels to add to the indexer pods.                                                   | `{}`                                                           |
| `indexer.updateStrategy`                     | updateStrategy for the statefulset.                                                        | `RollingUpdate`                                                |
| `indexer.images.repository`                  | name of the image used.                                                                    | `wazuh/wazuh-indexer`                                          |
| `indexer.images.tag`                         | Tag of the image.                                                                          | `4.14.3`                                                       |
| `indexer.images.pullPolicy`                  | pullPolicy of the image.                                                                   | `IfNotPresent`                                                 |
| `indexer.images.imagePullSecrets.enabled`    | Enable pulling image using secret.                                                         | `false`                                                        |
| `indexer.images.imagePullSecrets.secret`     | Map of secret names to authenticate.                                                       | `{}`                                                           |
| `indexer.resources.requests.cpu`             | Minimum CPU assigned to the pod.                                                           | `500m`                                                         |
| `indexer.resources.requests.memory`          | Minimum memory assigned to the pod.                                                        | `1Gi`                                                          |
| `indexer.resources.limits.cpu`               | Maximum CPU used by the pod.                                                               | `1000m`                                                        |
| `indexer.resources.limits.memory`            | Maximum memory used by the pod.                                                            | `2Gi`                                                          |
| `indexer.pdb.enabled`                        | Enables pdb for indexer.                                                                   | `true`                                                         |
| `indexer.livenessProbe.periodSeconds`        | How often to perform the probe.                                                            | `20`                                                           |
| `indexer.livenessProbe.timeoutSeconds`       | When the probe times out.                                                                  | `5`                                                            |
| `indexer.livenessProbe.failureThreshold`     | Minimum failures for the probe to be considered failed after having succeeded.             | `10`                                                           |
| `indexer.livenessProbe.successThreshold`     | Minimum successes for the probe to be considered successful after having failed.           | `1`                                                            |
| `indexer.livenessProbe.initialDelaySeconds`  | Delay before liveness probe is initiated.                                                  | `10`                                                           |
| `indexer.readinessProbe.periodSeconds`       | How often to perform the probe.                                                            | `20`                                                           |
| `indexer.readinessProbe.timeoutSeconds`      | When the probe times out.                                                                  | `5`                                                            |
| `indexer.readinessProbe.failureThreshold`    | Minimum failures for the probe to be considered failed after having succeeded.             | `10`                                                           |
| `indexer.readinessProbe.successThreshold`    | Minimum successes for the probe to be considered successful after having failed.           | `1`                                                            |
| `indexer.readinessProbe.initialDelaySeconds` | Delay before liveness probe is initiated.                                                  | `10`                                                           |
| `indexer.securityContext.fsGroup`            | Set the pods Security Context fsGroup.                                                     | `1000`                                                         |
| `indexer.networkPolicy.enabled`              | Specifies whether a NetworkPolicy should be created.                                       | `true`                                                         |
| `indexer.networkPolicy.extraIngresses`       | specify additional ingress rules for the NetworkPolicy.                                    | `[]`                                                           |
| `indexer.networkPolicy.extraEgresses`        | specify additional egress rules for the NetworkPolicy.                                     | `[]`                                                           |
| `indexer.service.type`                       | Type of the created service.                                                               | `ClusterIP`                                                    |
| `indexer.service.annotations`                | Annotations of the created service.                                                        | `{}`                                                           |
| `indexer.service.httpPort`                   | Port for the http endpoint.                                                                | `9200`                                                         |
| `indexer.service.nodes`                      | Port for the nodes endpoint.                                                               | `9300`                                                         |
| `indexer.service.metrics`                    | Port for the metrics endpoint.                                                             | `9600`                                                         |
| `indexer.nodeSelector`                       | nodeSelector                                                                               | `{}`                                                           |
| `indexer.tolerations`                        | Tolerations for indexer pods                                                               | `[]`                                                           |
| `indexer.affinity`                           | Affinity rules for indexer pods                                                            | `{}`                                                           |
| `indexer.dnsPolicy`                          | DNS policy for the pod                                                                     | `""`                                                           |
| `indexer.dnsConfig`                          | DNS configuration for the pod                                                              | `{}`                                                           |
| `indexer.additionalEnv`                      | Possibility to define additional env vars in the pod.                                      | `[]`                                                           |
| `indexer.additionalVolumes`                  | Possibility to define additional volumes in the pod.                                       | `[]`                                                           |
| `indexer.additionalVolumeMounts`             | Possibility to define additional volumeMounts in the pod.                                  | `[]`                                                           |
| `indexer.config.opensearch`                  | Override for opensearch.yml. If empty, the chart default is used.                          | `""`                                                           |
| `indexer.config.internalUsers`               | Override for internal_users.yml. If empty, the chart default is used.                      | `""`                                                           |
| `indexer.config.securityConfig`              | Override for config.yml (OpenSearch security config). If empty, the chart default is used. | `""`                                                           |
| `indexer.config.rolesMapping`                | Override for roles_mapping.yml. If empty, the chart default is used.                       | `""`                                                           |
| `indexer.config.roles`                       | Override for roles.yml. If empty, the chart default is used.                               | `""`                                                           |
| `indexer.config.tenants`                     | Override for tenants.yml. If empty, the chart default is used.                             | `""`                                                           |
| `indexer.config.nodesDn`                     | Override for nodes_dn.yml. If empty, the chart default is used.                            | `""`                                                           |
| `indexer.config.whitelist`                   | Override for whitelist.yml. If empty, the chart default is used.                           | `""`                                                           |
| `indexer.additionalConfigs`                  | Additional configurations to add to the configmap                                          | `{}`                                                           |
| `indexer.ldap.enabled`                       | Enable LDAP authentication domain                                                          | `false`                                                        |
| `indexer.ldap.order`                         | Auth domain order (lower = higher priority)                                                | `5`                                                            |
| `indexer.ldap.enableSSL`                     | Enable SSL                                                                                 | `false`                                                        |
| `indexer.ldap.enableStartTLS`                | Enable Start TLS                                                                           | `false`                                                        |
| `indexer.ldap.enableSSLClientAuth`           | Enable SSL client auth                                                                     | `false`                                                        |
| `indexer.ldap.verifyHostnames`               | Verify hostnames                                                                           | `true`                                                         |
| `indexer.ldap.hosts`                         | List of LDAP hosts (host:port)                                                             | `["localhost:389"]`                                            |
| `indexer.ldap.bindDn`                        | Distinguished name for LDAP bind user                                                      | `nil`                                                          |
| `indexer.ldap.existingSecret`                | Kubernetes Secret containing the LDAP bind password                                        | `""`                                                           |
| `indexer.ldap.bindPasswordKey`               | Key in the secret containing the bind password                                             | `password`                                                     |
| `indexer.ldap.userbase`                      | LDAP search base for users                                                                 | `ou=people,dc=example,dc=com`                                  |
| `indexer.ldap.usersearch`                    | LDAP user search filter ({0} is replaced with the username)                                | `(sAMAccountName={0})`                                         |
| `indexer.ldap.usernameAttribute`             | LDAP attribute used as username (null = use DN)                                            | `nil`                                                          |
| `indexer.initContainers`                     | Possibility to define additional init containers in the pod.                               | `[]`                                                           |
| `indexer.pvc.extraLabels`                    | Add addtional labels to the PersistentVolumeClaim metadata                                 | `{}`                                                           |
| `indexer.storageSize`                        | Defines the size of the pvc used by the statefulset.                                       | `50Gi`                                                         |
| `indexer.storageClass`                       | Defines the storageClass of the pvc used by the statefulset.                               | `nil`                                                          |
| `indexer.cred.existingSecret`                | Name of the existingSecret which holds the key "INDEXER_PASSWORD".                         | `""`                                                           |
| `indexer.cred.password`                      | Value of the password for the admin user.                                                  | `WazuhSecretPassword`                                          |
| `indexer.cred.passwordHash`                  | Hash of the password for the admin user.                                                   | `$2a$12$zGWIT7wkPKT/zww3bmMyp.KuWXH4RzgxiB91Q8NGFcqpyPy.R2Rcq` |

### indexer.snapshot Configuration for OpenSearch snapshot repositories.

| Name                                    | Description                                              | Value               |
| --------------------------------------- | -------------------------------------------------------- | ------------------- |
| `indexer.snapshot.enabled`              | Enable snapshot repository configuration on the indexer. | `false`             |
| `indexer.snapshot.fs.path`              | Path inside the container where snapshots are stored.    | `/mnt/snapshots`    |
| `indexer.snapshot.fs.storageSize`       | Size of the PVC used for the snapshot volume.            | `50Gi`              |
| `indexer.snapshot.fs.storageClass`      | StorageClass for the snapshot PVC.                       | `""`                |
| `indexer.snapshot.fs.accessModes`       | Access modes for the snapshot PVC.                       | `["ReadWriteMany"]` |
| `indexer.snapshot.fs.existingClaim`     | Name of an existing PVC to use instead of creating one.  | `""`                |
| `indexer.job.annotations`               | Annotations to add to the indexer job.                   | `{}`                |
| `indexer.job.resources.requests.cpu`    | Minimum CPU assigned to the job pod.                     | `100m`              |
| `indexer.job.resources.requests.memory` | Minimum memory assigned to the job pod.                  | `256Mi`             |
| `indexer.job.resources.limits.cpu`      | Maximum CPU used by the job pod.                         | `500m`              |
| `indexer.job.resources.limits.memory`   | Maximum memory used by the job pod.                      | `1Gi`               |

### dashboard configuration of the wazuh dashboard. Kibana for elasticsearch with Wazuh plugins

| Name                                           | Description                                                            | Value                                                          |
| ---------------------------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------- |
| `dashboard.enabled`                            | defines if we deploy dashboard or not                                  | `true`                                                         |
| `dashboard.serviceAccount.create`              | Create service account                                                 | `false`                                                        |
| `dashboard.serviceAccount.annotations`         | Annotations for service account                                        | `{}`                                                           |
| `dashboard.serviceAccount.name`                | Name of the service account                                            | `wazuh-dashboard`                                              |
| `dashboard.replicas`                           | number of replicas used in deployment.                                 | `1`                                                            |
| `dashboard.annotations`                        | additional annotations set on deployment.                              | `{}`                                                           |
| `dashboard.extraPodLabels`                     | Extra labels to add to the dashboard pods.                             | `{}`                                                           |
| `dashboard.images.repository`                  | name of the image used.                                                | `wazuh/wazuh-dashboard`                                        |
| `dashboard.images.tag`                         | Tag of the image.                                                      | `4.14.3`                                                       |
| `dashboard.images.pullPolicy`                  | pullPolicy of the image.                                               | `IfNotPresent`                                                 |
| `dashboard.images.updateStrategy`              | updateStrategy of the image.                                           | `OnDelete`                                                     |
| `dashboard.resources.requests.cpu`             | Minimum CPU assigned to the pod.                                       | `500m`                                                         |
| `dashboard.resources.requests.memory`          | Minimum memory assigned to the pod.                                    | `512Mi`                                                        |
| `dashboard.resources.limits.cpu`               | Maximum CPU used by the pod.                                           | `1000m`                                                        |
| `dashboard.resources.limits.memory`            | Maximum memory used by the pod.                                        | `1Gi`                                                          |
| `dashboard.pdb.enabled`                        | Enables pdb for dashboard.                                             | `false`                                                        |
| `dashboard.livenessProbe.periodSeconds`        | How often to perform the probe.                                        | `20`                                                           |
| `dashboard.livenessProbe.timeoutSeconds`       | When the probe times out.                                              | `5`                                                            |
| `dashboard.livenessProbe.failureThreshold`     | Minimum failures for the probe to be considered failed.                | `10`                                                           |
| `dashboard.livenessProbe.successThreshold`     | Minimum successes.                                                     | `1`                                                            |
| `dashboard.livenessProbe.initialDelaySeconds`  | Delay before liveness probe.                                           | `10`                                                           |
| `dashboard.readinessProbe.periodSeconds`       | How often to perform the probe.                                        | `20`                                                           |
| `dashboard.readinessProbe.timeoutSeconds`      | When the probe times out.                                              | `5`                                                            |
| `dashboard.readinessProbe.failureThreshold`    | Minimum failures for the probe to be considered failed.                | `10`                                                           |
| `dashboard.readinessProbe.successThreshold`    | Minimum successes.                                                     | `1`                                                            |
| `dashboard.readinessProbe.initialDelaySeconds` | Delay before liveness probe.                                           | `10`                                                           |
| `dashboard.securityContext`                    | Parameter to configure the securityContext of the pod.                 | `{}`                                                           |
| `dashboard.networkPolicy.enabled`              | Specifies whether a NetworkPolicy should be created.                   | `true`                                                         |
| `dashboard.networkPolicy.extraIngresses`       | specify additional ingress rules for the NetworkPolicy.                | `[]`                                                           |
| `dashboard.networkPolicy.extraEgresses`        | specify additional egress rules for the NetworkPolicy.                 | `[]`                                                           |
| `dashboard.service.type`                       | Type of the created service.                                           | `ClusterIP`                                                    |
| `dashboard.service.annotations`                | Annotations of the created service.                                    | `{}`                                                           |
| `dashboard.service.httpPort`                   | Port for the http endpoint.                                            | `5601`                                                         |
| `dashboard.nodeSelector`                       | nodeSelector                                                           | `{}`                                                           |
| `dashboard.tolerations`                        | Tolerations                                                            | `[]`                                                           |
| `dashboard.affinity`                           | Affinity                                                               | `{}`                                                           |
| `dashboard.dnsPolicy`                          | DNS policy for the pod                                                 | `""`                                                           |
| `dashboard.dnsConfig`                          | DNS configuration for the pod                                          | `{}`                                                           |
| `dashboard.additionalEnv`                      | Possibility to define additional env vars in the pod.                  | `[]`                                                           |
| `dashboard.enable_ssl`                         | with this you will be able to access kibana on http port instead of    | `false`                                                        |
| `dashboard.config`                             | Configuration of the dashboard parameters, this should not be changed. | `{{ include "wazuh.dashboard.config" . }}
`                    |
| `dashboard.cred.existingSecret`                | Name of the existingSecret                                             | `""`                                                           |
| `dashboard.cred.password`                      | Value of the password for the kibanaserver user.                       | `kibanaserver`                                                 |
| `dashboard.cred.username`                      | Value of the username                                                  | `kibanaserver`                                                 |
| `dashboard.cred.passwordHash`                  | Hash of the password                                                   | `$2a$12$7NCZ.l9ntPhou5zNjZIU4uqXNNWMF7SyF6Y6mcjhHTB6Z1eQubHC.` |
| `dashboard.basicAuth.enabled`                  | Enable basicAuth                                                       | `true`                                                         |
| `dashboard.basicAuth.order`                    | Order for basicAuth                                                    | `4`                                                            |
| `dashboard.basicAuth.challenge`                | Challenge for basicAuth                                                | `true`                                                         |
| `dashboard.server.extraConf`                   | Set extra config for Wazuh Dashboard                                   | `{}`                                                           |
| `dashboard.ingress.enabled`                    | Enable ingress record generation for dashboard.                        | `false`                                                        |
| `dashboard.ingress.className`                  | Defines the ingress class name used.                                   | `""`                                                           |
| `dashboard.ingress.tls`                        | Allows to use specific tls certificate.                                | `[]`                                                           |
| `dashboard.ingress.annotations`                | Used for detailed configuration.                                       | `{}`                                                           |
| `dashboard.ingress.host`                       | Defines the hostname and URL under which the dashboard gets            | `wazuh.example.com`                                            |

### wazuh configuration of the wazuh core component.

| Name                                            | Description                                                                        | Value                                  |
| ----------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------- |
| `wazuh.enabled`                                 | enable the deployment of wazuh core component                                      | `true`                                 |
| `wazuh.serviceAccount.create`                   | Create service account                                                             | `false`                                |
| `wazuh.serviceAccount.annotations`              | Annotations for service account                                                    | `{}`                                   |
| `wazuh.serviceAccount.name`                     | Name of the service account                                                        | `wazuh-manager`                        |
| `wazuh.syslog_enable`                           | Enables the syslog of the wazuh instance.                                          | `true`                                 |
| `wazuh.key`                                     | Defines the key of the wazuh cluster.                                              | `c98b62a9b6169ac5f67dae55ae4a9088`     |
| `wazuh.images.repository`                       | name of the image used.                                                            | `wazuh/wazuh-manager`                  |
| `wazuh.images.tag`                              | Tag of the image.                                                                  | `4.14.3`                               |
| `wazuh.images.pullPolicy`                       | pullPolicy of the image.                                                           | `IfNotPresent`                         |
| `wazuh.images.imagePullSecrets.enabled`         | Enable pulling image using secret.                                                 | `false`                                |
| `wazuh.images.imagePullSecrets.secret`          | Map of secret names to authenticate.                                               | `{}`                                   |
| `wazuh.loadBalancer.enabled`                    | Enable LoadBalancer service for external agent connections                         | `false`                                |
| `wazuh.loadBalancer.annotations`                | Annotations for LoadBalancer service                                               | `{}`                                   |
| `wazuh.service.annotations`                     | Annotations of the created service.                                                | `{}`                                   |
| `wazuh.service.port`                            | Port for the http endpoint.                                                        | `1516`                                 |
| `wazuh.nodeSelector`                            | nodeSelector                                                                       | `{}`                                   |
| `wazuh.apiCred.existingSecret`                  | name of the existingSecret                                                         | `""`                                   |
| `wazuh.apiCred.username`                        | name of the username.                                                              | `wazuh-wui`                            |
| `wazuh.apiCred.password`                        | password of the user.                                                              | `MyS3cr37P450r.*-`                     |
| `wazuh.authd.enabled`                           | enable password-based agent registration                                           | `true`                                 |
| `wazuh.authd.existingSecret`                    | name of the existingSecret                                                         | `""`                                   |
| `wazuh.authd.pass`                              | password of the authd.                                                             | `password`                             |
| `wazuh.initContainer.image`                     | Image used by the update-index container                                           | `alpine`                               |
| `wazuh.initContainer.resources.requests.cpu`    | Minimum CPU assigned to the pod.                                                   | `250m`                                 |
| `wazuh.initContainer.resources.requests.memory` | Minimum memory assigned to the pod.                                                | `512Mi`                                |
| `wazuh.initContainer.resources.limits.cpu`      | Maximum CPU used by the pod.                                                       | `1000m`                                |
| `wazuh.initContainer.resources.limits.memory`   | Maximum memory used by the pod.                                                    | `1Gi`                                  |
| `wazuh.extraInitContainers`                     | Parameters for the additional initContainers.                                      | `[]`                                   |
| `wazuh.script`                                  | Override for script.sh. If empty, files/script.sh is used.                         | `""`                                   |
| `wazuh.masterConf`                              | Override for master.conf. If empty, the generated ossec config is used.            | `""`                                   |
| `wazuh.workerConf`                              | Override for worker.conf. If empty, the generated ossec config is used.            | `""`                                   |
| `wazuh.localDecoder`                            | Override for local_decoder.xml. If empty, files/local_decoder.xml is used.         | `""`                                   |
| `wazuh.localRules`                              | Override for local_rules.xml. If empty, files/local_rules.xml is used.             | `""`                                   |
| `wazuh.internalOptions`                         | Override for internal_options.conf. If empty, files/internal_options.conf is used. | `""`                                   |
| `wazuh.master.enabled`                          | Enable the master                                                                  | `true`                                 |
| `wazuh.master.annotations`                      | additional annotations set on statefulset.                                         | `{}`                                   |
| `wazuh.master.extraPodLabels`                   | Extra labels to add to the master pods.                                            | `{}`                                   |
| `wazuh.master.resources.requests.cpu`           | Minimum CPU assigned to the pod.                                                   | `500m`                                 |
| `wazuh.master.resources.requests.memory`        | Minimum memory assigned to the pod.                                                | `512Mi`                                |
| `wazuh.master.resources.limits.cpu`             | Maximum CPU used by the pod.                                                       | `1000m`                                |
| `wazuh.master.resources.limits.memory`          | Maximum memory used by the pod.                                                    | `1Gi`                                  |
| `wazuh.master.tolerations`                      | Tolerations for master pods                                                        | `[]`                                   |
| `wazuh.master.affinity`                         | Affinity rules for master pods                                                     | `{}`                                   |
| `wazuh.master.dnsPolicy`                        | DNS policy for the pod                                                             | `""`                                   |
| `wazuh.master.dnsConfig`                        | DNS configuration for the pod                                                      | `{}`                                   |
| `wazuh.master.service.type`                     | Type of the created service.                                                       | `ClusterIP`                            |
| `wazuh.master.service.annotations`              | Annotations of the created service.                                                | `{}`                                   |
| `wazuh.master.configVolume.defaultMode`         | defaultMode for the manager config volume. If not set, defaults to 0500.           | `0755`                                 |
| `wazuh.master.livenessProbe`                    | Parameter to configure the livenessProbe.                                          | `{}`                                   |
| `wazuh.master.readinessProbe`                   | Parameter to configure the readinessProbe.                                         | `{}`                                   |
| `wazuh.master.additionalEnv`                    | Possibility to define additional env vars in the pod.                              | `[]`                                   |
| `wazuh.master.additionalVolumes`                | Possibility to define additional volumes in the pod.                               | `[]`                                   |
| `wazuh.master.additionalVolumeMounts`           | Possibility to define additional volumeMounts in the pod.                          | `[]`                                   |
| `wazuh.master.securityContext.capabilities.add` | Additional capabilities.                                                           | `["SYS_CHROOT"]`                       |
| `wazuh.master.networkPolicy.enabled`            | Specifies whether a NetworkPolicy should be created.                               | `true`                                 |
| `wazuh.master.networkPolicy.extraIngresses`     | specify additional ingress rules                                                   | `[]`                                   |
| `wazuh.master.networkPolicy.extraEgresses`      | specify additional egress rules                                                    | `[]`                                   |
| `wazuh.master.pvc.extraLabels`                  | Add addtional labels to the PersistentVolumeClaim metadata                         | `{}`                                   |
| `wazuh.master.storageSize`                      | Defines the size of the pvc used by the statefulset.                               | `50Gi`                                 |
| `wazuh.master.storageClass`                     | Defines the storageClass of the pvc used by the statefulset.                       | `nil`                                  |
| `wazuh.master.conf`                             | Config for the wazuh master, do not change!                                        | `{{ include "wazuh.master.conf" . }}
` |
| `wazuh.master.extraConf`                        | Gets appended to the wazuh.master.conf.                                            | `""`                                   |
| `wazuh.worker.enabled`                          | Enable the worker                                                                  | `true`                                 |
| `wazuh.worker.replicas`                         | number of replicas used in statefulset.                                            | `2`                                    |
| `wazuh.worker.annotations`                      | additional annotations set on deployment.                                          | `{}`                                   |
| `wazuh.worker.extraPodLabels`                   | Extra labels to add to the worker pods.                                            | `{}`                                   |
| `wazuh.worker.resources.requests.cpu`           | Minimum CPU assigned to the pod.                                                   | `500m`                                 |
| `wazuh.worker.resources.requests.memory`        | Minimum memory assigned to the pod.                                                | `512Mi`                                |
| `wazuh.worker.resources.limits.cpu`             | Maximum CPU used by the pod.                                                       | `1000m`                                |
| `wazuh.worker.resources.limits.memory`          | Maximum memory used by the pod.                                                    | `1Gi`                                  |
| `wazuh.worker.tolerations`                      | Tolerations for worker pods                                                        | `[]`                                   |
| `wazuh.worker.affinity`                         | Affinity rules for worker pods                                                     | `{}`                                   |
| `wazuh.worker.dnsPolicy`                        | DNS policy for the pod                                                             | `""`                                   |
| `wazuh.worker.dnsConfig`                        | DNS configuration for the pod                                                      | `{}`                                   |
| `wazuh.worker.configVolume.defaultMode`         | defaultMode for the worker config volume. If not set, defaults to 0500.            | `0755`                                 |
| `wazuh.worker.podAntiAffinity`                  | Pod anti-affinity setting                                                          | `soft`                                 |
| `wazuh.worker.podAntiAffinityTopologyKey`       | Topology key for anti-affinity                                                     | `kubernetes.io/hostname`               |
| `wazuh.worker.service.type`                     | Type of the created service.                                                       | `ClusterIP`                            |
| `wazuh.worker.service.annotations`              | Annotations of the created service.                                                | `{}`                                   |
| `wazuh.worker.pdb.enabled`                      | Enables pdb for worker.                                                            | `true`                                 |
| `wazuh.worker.livenessProbe`                    | Parameter to configure the livenessProbe.                                          | `{}`                                   |
| `wazuh.worker.readinessProbe`                   | Parameter to configure the readinessProbe.                                         | `{}`                                   |
| `wazuh.worker.additionalEnv`                    | Possibility to define additional env vars in the pod.                              | `[]`                                   |
| `wazuh.worker.additionalVolumes`                | Possibility to define additional volumes vars in the pod.                          | `[]`                                   |
| `wazuh.worker.additionalVolumeMounts`           | Possibility to define additional volumeMounts vars in the pod.                     | `[]`                                   |
| `wazuh.worker.securityContext.capabilities.add` | Additional capabilities.                                                           | `["SYS_CHROOT"]`                       |
| `wazuh.worker.networkPolicy.enabled`            | Specifies whether a NetworkPolicy should be created.                               | `true`                                 |
| `wazuh.worker.networkPolicy.extraIngresses`     | specify additional ingress rules                                                   | `[]`                                   |
| `wazuh.worker.networkPolicy.extraEgresses`      | specify additional egress rules                                                    | `[]`                                   |
| `wazuh.worker.pvc.extraLabels`                  | Add addtional labels to the PersistentVolumeClaim metadata                         | `{}`                                   |
| `wazuh.worker.storageSize`                      | Defines the size of the pvc used by the statefulset.                               | `50Gi`                                 |
| `wazuh.worker.storageClass`                     | Defines the storageClass of the pvc used by the statefulset.                       | `nil`                                  |
| `wazuh.worker.conf`                             | Config for the wazuh worker, do not change!                                        | `{{ include "wazuh.worker.conf" . }}
` |
| `wazuh.worker.extraConf`                        | Gets appended to the wazuh.worker.conf.                                            | `""`                                   |
| `agent.enabled`                                 | Enable the agent.                                                                  | `true`                                 |
| `agent.namePrefix`                              | Prefix for the agent name.                                                         | `""`                                   |
| `agent.serviceAccount.create`                   | defines wazuh agent serviceAccount.                                                | `false`                                |
| `agent.serviceAccount.annotations`              | Annotations for the service account                                                | `{}`                                   |
| `agent.serviceAccount.name`                     | Name of the service account                                                        | `wazuh-agent`                          |
| `agent.debug.enabled`                           | Enable debug mode for the agent.                                                   | `false`                                |
| `agent.debug.level`                             | Run the agent processes in debug mode.                                             | `1`                                    |
| `agent.debug.modules`                           | List of agent processes for which debugging is enabled.                            | `["agent","wazuh_modules"]`            |
| `agent.service.port`                            | Port for the service.                                                              | `5000`                                 |
| `agent.service.type`                            | Type of the created service.                                                       | `ClusterIP`                            |
| `agent.service.annotations`                     | Annotations of the created service.                                                | `{}`                                   |
| `agent.labels`                                  | Extra labels for the agent.                                                        | `{}`                                   |
| `agent.annotations`                             | Extra annotations for the agent.                                                   | `{}`                                   |
| `agent.podAnnotations`                          | Extra annotations for the agent.                                                   | `{}`                                   |
| `agent.extraPodLabels`                          | Extra labels to add to the agent pods.                                             | `{}`                                   |
| `agent.images.repository`                       | Repository                                                                         | `kinseii/wazuh-agent`                  |
| `agent.images.tag`                              | Tag                                                                                | `4.14.1`                               |
| `agent.images.pullPolicy`                       | Pull Policy                                                                        | `IfNotPresent`                         |
| `agent.podSecurityContext`                      | Additional capabilities.                                                           | `{}`                                   |
| `agent.nodeSelector`                            | nodeSelector                                                                       | `{}`                                   |
| `agent.affinity`                                | affinity                                                                           | `{}`                                   |
| `agent.tolerations`                             | tolerations                                                                        | `[]`                                   |
| `agent.dnsPolicy`                               | DNS policy for the pod.                                                            | `""`                                   |
| `agent.dnsConfig`                               | DNS configuration for the pod.                                                     | `{}`                                   |
