# wazuh

![Version: 0.1.1](https://img.shields.io/badge/Version-0.1.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 4.11.1](https://img.shields.io/badge/AppVersion-4.11.1-informational?style=flat-square)

Wazuh is a free and open source security platform that unifies XDR and SIEM protection for endpoints and cloud workloads.

**Homepage:** <https://wazuh.com/>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| Dani | <andre.gomes@promptlyhealth.com> | <https://github.com/Ca-moes> |
| Morgoved |  | <https://github.com/morgoved> |
| 71g3pf4c3 |  | <https://github.com/71g3pf4c3> |

## Source Code

* <https://github.com/morgoved/wazuh-helm>

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://charts.jetstack.io | cert-manager | 1.16.3 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| autoreload.enabled | bool | `false` |  |
| cert-manager.enabled | bool | `false` |  |
| certificates.duration | string | `"2160h"` |  |
| certificates.renewBefore | string | `"360h"` |  |
| certificates.subject.country | string | `"US"` |  |
| certificates.subject.locality | string | `"California"` |  |
| certificates.subject.organization | string | `"Company"` |  |
| dashboard.additionalEnv | list | `[]` |  |
| dashboard.annotations | object | `{}` |  |
| dashboard.config | string | `"{{ include \"wazuh.dashboard.config\" . }}\n"` |  |
| dashboard.cred.existingSecret | string | `""` |  |
| dashboard.cred.password | string | `"kibanaserver"` |  |
| dashboard.cred.username | string | `"kibanaserver"` |  |
| dashboard.enable_ssl | bool | `false` |  |
| dashboard.images.pullPolicy | string | `"IfNotPresent"` |  |
| dashboard.images.repository | string | `"wazuh/wazuh-dashboard"` |  |
| dashboard.images.tag | string | `"4.11.1"` |  |
| dashboard.images.updateStrategy | string | `"OnDelete"` |  |
| dashboard.ingress.annotations | object | `{}` |  |
| dashboard.ingress.className | string | `""` |  |
| dashboard.ingress.enabled | bool | `false` |  |
| dashboard.ingress.host | string | `"wazuh.example.com"` |  |
| dashboard.ingress.tls | list | `[]` |  |
| dashboard.livenessProbe.failureThreshold | int | `10` |  |
| dashboard.livenessProbe.httpGet.path | string | `"/api/status"` |  |
| dashboard.livenessProbe.httpGet.port | int | `5601` |  |
| dashboard.livenessProbe.initialDelaySeconds | int | `10` |  |
| dashboard.livenessProbe.periodSeconds | int | `20` |  |
| dashboard.livenessProbe.successThreshold | int | `1` |  |
| dashboard.livenessProbe.timeoutSeconds | int | `5` |  |
| dashboard.networkPolicy.enabled | bool | `true` |  |
| dashboard.pdb.enabled | bool | `false` |  |
| dashboard.pdb.maxUnavailable | int | `1` |  |
| dashboard.readinessProbe.failureThreshold | int | `10` |  |
| dashboard.readinessProbe.httpGet.path | string | `"/api/status"` |  |
| dashboard.readinessProbe.httpGet.port | int | `5601` |  |
| dashboard.readinessProbe.initialDelaySeconds | int | `10` |  |
| dashboard.readinessProbe.periodSeconds | int | `20` |  |
| dashboard.readinessProbe.successThreshold | int | `1` |  |
| dashboard.readinessProbe.timeoutSeconds | int | `5` |  |
| dashboard.replicas | int | `1` |  |
| dashboard.resources.limits.memory | string | `"1Gi"` |  |
| dashboard.resources.requests.cpu | string | `"500m"` |  |
| dashboard.resources.requests.memory | string | `"512Mi"` |  |
| dashboard.securityContext | object | `{}` |  |
| dashboard.service.annotations | object | `{}` |  |
| dashboard.service.httpPort | int | `5601` |  |
| dashboard.service.type | string | `"ClusterIP"` |  |
| fullnameOverride | string | `nil` |  |
| indexer.additionalEnv | list | `[]` |  |
| indexer.annotations | object | `{}` |  |
| indexer.config.internalUsers | string | `"{{ include \"wazuh.indexer.internalUsers\" . }}"` |  |
| indexer.config.opensearch | string | `"{{ include \"wazuh.indexer.opensearchConfig\" . }}"` |  |
| indexer.config.roles | string | `"{{ include \"wazuh.indexer.roles\" . }}"` |  |
| indexer.config.rolesMapping | string | `"{{ include \"wazuh.indexer.rolesMapping\" . }}"` |  |
| indexer.config.securityConfig | string | `"{{ include \"wazuh.indexer.securityConfig\" . }}"` |  |
| indexer.cred.existingSecret | string | `""` |  |
| indexer.cred.password | string | `"SecretPassword"` |  |
| indexer.cred.username | string | `"admin"` |  |
| indexer.env.CLUSTER_NAME | string | `"wazuh"` |  |
| indexer.env.DISABLE_INSTALL_DEMO_CONFIG | string | `"true"` |  |
| indexer.env.NETWORK_HOST | string | `"0.0.0.0"` |  |
| indexer.env.OPENSEARCH_JAVA_OPTS | string | `"-Xms1g -Xmx1g -Dlog4j2.formatMsgNoLookups=true"` |  |
| indexer.images.imagePullSecrets.enabled | bool | `false` |  |
| indexer.images.imagePullSecrets.secret | object | `{}` |  |
| indexer.images.pullPolicy | string | `"IfNotPresent"` |  |
| indexer.images.repository | string | `"wazuh/wazuh-indexer"` |  |
| indexer.images.tag | string | `"4.11.1"` |  |
| indexer.initContainers.volumeMountHack.resources.limits.memory | string | `"256Mi"` |  |
| indexer.initContainers.volumeMountHack.resources.requests.cpu | string | `"50m"` |  |
| indexer.initContainers.volumeMountHack.resources.requests.memory | string | `"128Mi"` |  |
| indexer.livenessProbe.failureThreshold | int | `10` |  |
| indexer.livenessProbe.initialDelaySeconds | int | `10` |  |
| indexer.livenessProbe.periodSeconds | int | `20` |  |
| indexer.livenessProbe.successThreshold | int | `1` |  |
| indexer.livenessProbe.tcpSocket.port | int | `9200` |  |
| indexer.livenessProbe.timeoutSeconds | int | `5` |  |
| indexer.networkPolicy.enabled | bool | `true` |  |
| indexer.pdb.enabled | bool | `true` |  |
| indexer.pdb.maxUnavailable | int | `1` |  |
| indexer.plugins | list | `[]` |  |
| indexer.readinessProbe.failureThreshold | int | `10` |  |
| indexer.readinessProbe.initialDelaySeconds | int | `10` |  |
| indexer.readinessProbe.periodSeconds | int | `20` |  |
| indexer.readinessProbe.successThreshold | int | `1` |  |
| indexer.readinessProbe.tcpSocket.port | int | `9200` |  |
| indexer.readinessProbe.timeoutSeconds | int | `5` |  |
| indexer.replicas | int | `3` |  |
| indexer.resources.limits.memory | string | `"2Gi"` |  |
| indexer.resources.requests.cpu | string | `"500m"` |  |
| indexer.resources.requests.memory | string | `"1Gi"` |  |
| indexer.securityContext.fsGroup | int | `1000` |  |
| indexer.service.annotations | object | `{}` |  |
| indexer.service.httpPort | int | `9200` |  |
| indexer.service.metrics | int | `9600` |  |
| indexer.service.nodes | int | `9300` |  |
| indexer.service.type | string | `"ClusterIP"` |  |
| indexer.storageClass | string | `nil` |  |
| indexer.storageSize | string | `"50Gi"` |  |
| indexer.updateStrategy | string | `"RollingUpdate"` |  |
| nameOverride | string | `nil` |  |
| wazuh.agentGroupConf[0].agent | string | `"<agent_config>\n  <localfile>\n    <location>journald</location>\n    <log_format>journald</log_format>\n  </localfile>\n  <localfile>\n    <location>/var/log/falco.log</location>\n    <log_format>json</log_format>\n  </localfile>\n  <wodle name=\"docker-listener\">\n    <interval>10m</interval>\n    <attempts>5</attempts>\n    <run_on_start>no</run_on_start>\n    <disabled>no</disabled>\n  </wodle>\n</agent_config>\n"` |  |
| wazuh.agentGroupConf[0].merged | string | `"#cloud\n!228 ar.conf\nrestart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\nrestart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\nrestart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n!435 agent.conf\n  <agent_config>\n    <localfile>\n      <location>journald</location>\n      <log_format>journald</log_format>\n    </localfile>\n    <localfile>\n      <location>/var/log/falco.log</location>\n      <log_format>json</log_format>\n    </localfile>\n    <wodle name=\"docker-listener\">\n      <interval>10m</interval>\n      <attempts>5</attempts>\n      <run_on_start>no</run_on_start>\n      <disabled>no</disabled>\n    </wodle>\n  </agent_config>\n"` |  |
| wazuh.agentGroupConf[0].name | string | `"example"` |  |
| wazuh.apiCred.existingSecret | string | `""` |  |
| wazuh.apiCred.password | string | `"MyS3cr37P450r.*-"` |  |
| wazuh.apiCred.username | string | `"wazuh-wui"` |  |
| wazuh.authd.existingSecret | string | `""` |  |
| wazuh.authd.pass | string | `"password"` |  |
| wazuh.env.FILEBEAT_SSL_VERIFICATION_MODE | string | `"full"` |  |
| wazuh.images.pullPolicy | string | `"IfNotPresent"` |  |
| wazuh.images.pullSecret | string | `"regcred"` |  |
| wazuh.images.repository | string | `"wazuh/wazuh-manager"` |  |
| wazuh.images.tag | string | `"4.11.1"` |  |
| wazuh.initContainer.resources | object | `{}` |  |
| wazuh.internalOptions | string | `"{{ include \"wazuh.internalOptions\" . }}\n"` |  |
| wazuh.key | string | `"c98b62a9b6169ac5f67dae55ae4a9088"` |  |
| wazuh.localDecoder | string | `"{{ include \"wazuh.localDecoder\" . }}\n"` |  |
| wazuh.localRules | string | `"{{ include \"wazuh.localRules\" . }}\n"` |  |
| wazuh.master.annotations | object | `{}` |  |
| wazuh.master.conf | string | `"{{ include \"wazuh.master.conf\" . }}\n"` |  |
| wazuh.master.extraConf | string | `""` |  |
| wazuh.master.livenessProbe | object | `{}` |  |
| wazuh.master.networkPolicy.enabled | bool | `true` |  |
| wazuh.master.readinessProbe | object | `{}` |  |
| wazuh.master.resources.limits.memory | string | `"1Gi"` |  |
| wazuh.master.resources.requests.cpu | string | `"500m"` |  |
| wazuh.master.resources.requests.memory | string | `"512Mi"` |  |
| wazuh.master.securityContext.capabilities.add[0] | string | `"SYS_CHROOT"` |  |
| wazuh.master.service.annotations | object | `{}` |  |
| wazuh.master.service.ports.api | int | `55000` |  |
| wazuh.master.service.ports.registration | int | `1515` |  |
| wazuh.master.service.type | string | `"ClusterIP"` |  |
| wazuh.master.storageClass | string | `nil` |  |
| wazuh.master.storageSize | string | `"50Gi"` |  |
| wazuh.service.annotations | object | `{}` |  |
| wazuh.service.port | int | `1516` |  |
| wazuh.syslog_enable | bool | `true` |  |
| wazuh.worker.annotations | object | `{}` |  |
| wazuh.worker.conf | string | `"{{ include \"wazuh.worker.conf\" . }}\n"` |  |
| wazuh.worker.extraConf | string | `""` |  |
| wazuh.worker.livenessProbe | object | `{}` |  |
| wazuh.worker.networkPolicy.enabled | bool | `true` |  |
| wazuh.worker.pdb.enabled | bool | `true` |  |
| wazuh.worker.pdb.maxUnavailable | int | `1` |  |
| wazuh.worker.readinessProbe | object | `{}` |  |
| wazuh.worker.replicas | int | `2` |  |
| wazuh.worker.resources.limits.memory | string | `"1Gi"` |  |
| wazuh.worker.resources.requests.cpu | string | `"500m"` |  |
| wazuh.worker.resources.requests.memory | string | `"512Mi"` |  |
| wazuh.worker.securityContext.capabilities.add[0] | string | `"SYS_CHROOT"` |  |
| wazuh.worker.service.annotations | object | `{}` |  |
| wazuh.worker.service.ports.agentEvents | int | `1514` |  |
| wazuh.worker.service.type | string | `"ClusterIP"` |  |
| wazuh.worker.storageClass | string | `nil` |  |
| wazuh.worker.storageSize | string | `"50Gi"` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
