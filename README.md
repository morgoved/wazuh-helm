# wazuh-kubernetes-helmchart

![Version: 0.0.1](https://img.shields.io/badge/Version-0.0.1-informational?style=flat-square) ![AppVersion: 4.8.0](https://img.shields.io/badge/AppVersion-4.8.0-informational?style=flat-square)

Wazuh is centralized Security Information Event Management(SIEM) and Vulnerability inteligence and threat monitoring application
For generate certificates pls follow this https://github.com/wazuh/wazuh-kubernetes/blob/master/instructions.md
For get hashes you can run docker run --rm -ti wazuh/wazuh-indexer:4.6.0 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
All changes into indexer configuration also into secrets will apply auto by job hooks - reloader check changes.
You can see example folder as work production configuration.
Already tested at 4.6.0 version.
Wazuh can have only one master node (configuration ready to use it in multi master but wazuh not support it).
All xml configuration apply auto changes by init containers.

This fork open in any time to contributors and also open to move into official repo for wazuh project.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| dashboard.deployment.enabled | bool | `true` |  |
| dashboard.enable_ssl | bool | `false` |  |
| dashboard.env.INDEXER_URL | string | `"https://wazuh-sand-indexer-rest"` |  |
| dashboard.env.WAZUH_API_HOST | string | `"wazuh-manager-master-0.wazuh-sand-cluster"` |  |
| dashboard.env.WAZUH_API_URL | string | `"https://wazuh-manager-master-0.wazuh-sand-cluster"` |  |
| dashboard.images.pullPolicy | string | `"IfNotPresent"` |  |
| dashboard.images.repository | string | `"wazuh/wazuh-dashboard"` |  |
| dashboard.images.resources.limits.cpu | string | `"900m"` |  |
| dashboard.images.resources.limits.memory | string | `"1Gi"` |  |
| dashboard.images.resources.requests.cpu | string | `"500m"` |  |
| dashboard.images.resources.requests.memory | string | `"512Mi"` |  |
| dashboard.images.tag | string | `"4.6.0"` |  |
| dashboard.images.updateStrategy | string | `"OnDelete"` |  |
| dashboard.replicas | int | `1` |  |
| dashboard.service.httpPort | int | `5601` |  |
| dashboard.service.type | string | `"ClusterIP"` |  |
| identifier.appId | string | `"sand"` |  |
| identifier.appName | string | `"wazuh"` |  |
| indexer.config | string | `nil` |  |
| indexer.deployment.enabled | bool | `true` |  |
| indexer.env.ALLOW_DEMOCERTIFICATES | string | `"false"` |  |
| indexer.env.CLUSTER_NAME | string | `"wazuh"` |  |
| indexer.env.DISABLE_INSTALL_DEMO_CONFIG | string | `"true"` |  |
| indexer.env.DISCOVERY_SERVICE | string | `"wazuh-sand-indexer-nodes"` |  |
| indexer.env.HTTP_CORS_ENABLE | string | `"false"` |  |
| indexer.env.NETWORK_HOST | string | `"0.0.0.0"` |  |
| indexer.env.NUMBER_OF_MASTERS | string | `"3"` |  |
| indexer.images.imagePullSecrets.enabled | bool | `false` |  |
| indexer.images.imagePullSecrets.secret | object | `{}` |  |
| indexer.images.pullPolicy | string | `"IfNotPresent"` |  |
| indexer.images.replicaCount | int | `3` |  |
| indexer.images.repository | string | `"wazuh/wazuh-indexer"` |  |
| indexer.images.resources.limits.cpu | string | `"800m"` |  |
| indexer.images.resources.limits.memory | string | `"2Gi"` |  |
| indexer.images.resources.requests.cpu | string | `"500m"` |  |
| indexer.images.resources.requests.memory | string | `"1Gi"` |  |
| indexer.images.tag | string | `"4.6.0"` |  |
| indexer.images.updateStrategy | string | `"RollingUpdate"` |  |
| indexer.plugins | list | `[]` |  |
| indexer.replicas | int | `3` |  |
| indexer.selfcert.enabled | bool | `false` |  |
| indexer.service.httpPort | int | `9200` |  |
| indexer.service.metrics | int | `9600` |  |
| indexer.service.transport | int | `9300` |  |
| indexer.service.type | string | `"ClusterIP"` |  |
| indexer.storageClassName | string | `"gp2"` |  |
| indexer.storageSize | string | `"50Gi"` |  |
| ingress.annotations."kubernetes.io/ingress.class" | string | `"nginx"` |  |
| ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `"HTTPS"` |  |
| ingress.enabled | bool | `false` |  |
| ingress.host | string | `"wazuh.example.com"` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.annotation | null | `true` |  |
| wazuh.deployment.enabled | bool | `true` |  |
| wazuh.env.FILEBEAT_SSL_VERIFICATION_MODE | string | `"none"` |  |
| wazuh.images.pullSecret | string | `"regcred"` |  |
| wazuh.images.repository | string | `"wazuh/wazuh-manager"` |  |
| wazuh.images.resources.limits.cpu | string | `"850m"` |  |
| wazuh.images.resources.limits.memory | string | `"1Gi"` |  |
| wazuh.images.resources.requests.cpu | string | `"500m"` |  |
| wazuh.images.resources.requests.memory | string | `"500Mi"` |  |
| wazuh.images.tag | string | `"4.6.0"` |  |
| wazuh.images.worker_resources.limits.cpu | string | `"1500m"` |  |
| wazuh.images.worker_resources.limits.memory | string | `"2Gi"` |  |
| wazuh.images.worker_resources.requests.cpu | string | `"1000m"` |  |
| wazuh.images.worker_resources.requests.memory | string | `"1Gi"` |  |
| wazuh.key | string | `"c98b62a9b6169ac5f67dae55ae4a9088"` |  |
| wazuh.master_replicas | int | `1` |  |
| wazuh.service.annotations | string | `"null"` |  |
| wazuh.service.m_nodeType | string | `"master"` |  |
| wazuh.service.masterType | string | `"ClusterIP"` |  |
| wazuh.service.ports.agentEvents | int | `1514` |  |
| wazuh.service.ports.api | int | `55000` |  |
| wazuh.service.ports.registration | int | `1515` |  |
| wazuh.service.ports.wazuhInternal | int | `1516` |  |
| wazuh.service.type | string | `"ClusterIP"` |  |
| wazuh.service.w_nodeType | string | `"worker"` |  |
| wazuh.service.workerType | string | `"ClusterIP"` |  |
| wazuh.storageClassNameMaster | string | `"gp2"` |  |
| wazuh.storageClassNameWorker | string | `"gp2"` |  |
| wazuh.storageSizeMaster | string | `"50Gi"` |  |
| wazuh.storageSizeWorker | string | `"50Gi"` |  |
| wazuh.syslog_enable | bool | `true` |  |
| wazuh.worker_replicas | int | `2` |  |
