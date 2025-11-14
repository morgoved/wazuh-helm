# wazuh-kubernetes-helm-chart

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square)
![AppVersion: 4.14.1](https://img.shields.io/badge/AppVersion-4.14.1-informational?style=flat-square)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/wazuh-helm-morgoved)](https://artifacthub.io/packages/search?repo=wazuh-helm-morgoved)

Wazuh is a centralized Security Information and Event Management (SIEM) platform offering vulnerability intelligence and threat monitoring capabilities.

### Generating Certificates

To generate the necessary certificates, refer to the instructions available [here](https://github.com/wazuh/wazuh-kubernetes/blob/master/instructions.md).

### Retrieving Hashes

To retrieve hashes, execute the following command:

```bash
docker run --rm -ti wazuh/wazuh-indexer:4.14.1 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh`
```

### Automatic Configuration Updates

Any changes made to the indexer configuration or secrets will be automatically applied via job hooks. The [`reloader`](https://artifacthub.io/packages/helm/cloudnativeapp/reloader) monitors for updates to ensure seamless application of changes. For a practical example of a production configuration, check the example folder.

### Compatibility

This Helm chart has been tested with Wazuh version 4.14.1. Please note:

Wazuh supports only a single master node and multiple worker nodes. Although the configuration is prepared for a multi-master setup, Wazuh does not currently support this feature.
All XML configuration files are automatically updated through init containers.

### Contributing

This fork welcomes contributions and is open to transitioning into the official Wazuh project repository. Contributions are encouraged and appreciated.

## Values

To see all values and instructions, refer to the [README.md](./charts/wazuh/README.md) of the chart.
