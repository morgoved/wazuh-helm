{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "wazuh.name" -}}
{{- default "wazuh" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "wazuh.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- $name := default "wazuh" .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "wazuh.dashboard.config"}}
server.host: 0.0.0.0
server.port: {{ .Values.dashboard.service.httpPort }}
opensearch.hosts: "https://{{ include "wazuh.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}"
opensearch.ssl.verificationMode: none
opensearch.requestHeadersWhitelist: [ authorization,securitytenant ]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
opensearch_security.auth.unauthenticated_routes: ['/api/stats', '/api/status']
server.ssl.enabled: {{ .Values.dashboard.enable_ssl }}
server.ssl.key: "/usr/share/wazuh-dashboard/certs/key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/cert.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wz-home
{{- end }}

{{/* Snippet for the configuration file used by wazuh master */}}
{{- define "wazuh.master.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, master node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>{{ .Values.wazuh.worker.service.ports.agentEvents }}</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://{{ include "wazuh.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!--
  <active-response>
    active-response options here
  </active-response>
  -->

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
      <enabled>yes</enabled>
      <threads>1</threads>
      <max_sessions>64</max_sessions>
      <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
    <port>{{ .Values.wazuh.master.service.ports.registration }}</port>
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-master-0</node_name>
    <node_type>master</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>wazuh-manager-master-0.wazuh-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  {{- if .Values.wazuh.master.extraConf }}
  {{ .Values.wazuh.master.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}

{{/* Snippet for the configuration file used by wazuh worker */}}
{{- define "wazuh.worker.conf" }}
<!--
  Wazuh - Manager - Default configuration for ubuntu 16.04
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh

  Customization: TCP on port 1514
  Customization: Cluster mode enabled, worker node
-->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>ossecm@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <queue_size>131072</queue_size>
    <agents_disconnection_time>20s</agents_disconnection_time>
    <agents_disconnection_alert_time>100s</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>{{ .Values.wazuh.worker.service.ports.agentEvents }}</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_unixaudit>yes</check_unixaudit>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 12 hours -->
    <frequency>43200</frequency>

    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>

    <system_audit>/var/ossec/etc/rootcheck/system_audit_rcl.txt</system_audit>
    <system_audit>/var/ossec/etc/rootcheck/system_audit_ssh.txt</system_audit>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://{{ include "wazuh.fullname" . }}-indexer:{{ .Values.indexer.service.httpPort }}</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/ssl/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/ssl/filebeat.pem</certificate>
      <key>/etc/ssl/filebeat.key</key>
    </ssl>
  </indexer>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 12 hours -->
    <frequency>43200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Generate alert when new file detected -->
    <alert_new_files>yes</alert_new_files>

    <!-- Don't ignore files that change more than 'frequency' times -->
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>

    <!-- Remove not monitored files -->
    <remove_old_diff>yes</remove_old_diff>

    <!-- Allow the system to restart Auditd after installing the plugin -->
    <restart_audit>yes</restart_audit>
  </syscheck>

  <!-- Active response -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.66.0.2</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account.sh</executable>
    <expect>user</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-ossec</name>
    <executable>restart-ossec.sh</executable>
    <expect></expect>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null</name>
    <executable>route-null.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>win_route-null-2012</name>
    <executable>route-null-2012.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh</name>
    <executable>netsh.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>netsh-win-2016</name>
    <executable>netsh-win-2016.cmd</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!--
  <active-response>
    active-response options here
  </active-response>
  -->

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-sources</list>
    <list>etc/lists/amazon/aws-eventnames</list>

    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
	    <enabled>yes</enabled>
	    <threads>1</threads>
	    <max_sessions>64</max_sessions>
	    <session_timeout>15m</session_timeout>
  </rule_test>

  <!-- Configuration for ossec-authd
    To enable this service, run:
    wazuh-control enable auth
  -->
  <auth>
    <disabled>no</disabled>
    <port>{{ .Values.wazuh.master.service.ports.registration }}</port>
    <use_source_ip>no</use_source_ip>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>no</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>{{ include "wazuh.fullname" . }}-manager-worker-___INDEX___</node_name>
    <node_type>worker</node_type>
    <key>{{ .Values.wazuh.key }}</key>
    <port>{{ .Values.wazuh.service.port }}</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <!-- Kubernetes Service Pointing to Master node -->
        <node>wazuh-manager-master-0.wazuh-manager-cluster</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  {{- if .Values.wazuh.worker.extraConf }}
  {{ .Values.wazuh.worker.extraConf | indent 2 }}
  {{- end }}
</ossec_config>
{{- end }}

{{- define "wazuh.indexer.opensearchConfig"}}
cluster.name: ${CLUSTER_NAME}
node.name: ${NODE_NAME}
network.host: ${NETWORK_HOST}
discovery.seed_hosts: {{ include "wazuh.fullname" . }}-indexer-nodes
cluster.initial_master_nodes:
  - {{ include "wazuh.fullname" . }}-indexer-0

node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
plugins.security.ssl.http.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.http.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /usr/share/wazuh-indexer/certs/node.pem
plugins.security.ssl.transport.pemkey_filepath: /usr/share/wazuh-indexer/certs/node-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /usr/share/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false
plugins.security.authcz.admin_dn:
  - CN=admin,O=Company,L=California,C=US
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - CN={{ include "wazuh.fullname" . }}-indexer,O=Company,L=California,C=US
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"
plugins.security.allow_default_init_securityindex: true
cluster.routing.allocation.disk.threshold_enabled: false
compatibility.override_main_response_version: true
{{- end }}


{{- define "wazuh.indexer.internalUsers"}}
---
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: "internalusers"
  config_version: 2

# Define your internal users here

## Demo users

admin:
  hash: "$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

kibanaserver:
  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
  reserved: true
  description: "Demo kibanaserver user"

kibanaro:
  hash: "$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC"
  reserved: false
  backend_roles:
  - "kibanauser"
  - "readall"
  attributes:
    attribute1: "value1"
    attribute2: "value2"
    attribute3: "value3"
  description: "Demo kibanaro user"

logstash:
  hash: "$2a$12$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2"
  reserved: false
  backend_roles:
  - "logstash"
  description: "Demo logstash user"

readall:
  hash: "$2a$12$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2"
  reserved: false
  backend_roles:
  - "readall"
  description: "Demo readall user"

snapshotrestore:
  hash: "$2y$12$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W"
  reserved: false
  backend_roles:
  - "snapshotrestore"
  description: "Demo snapshotrestore user"
{{- end }}

{{- define "wazuh.indexer.rolesMapping"}}
---
# In this file users, backendroles and hosts can be mapped to Open Distro Security roles.
# Permissions for Opendistro roles are configured in roles.yml

_meta:
  type: "rolesmapping"
  config_version: 2

# Define your roles mapping here

## Default roles mapping

all_access:
  reserved: true
  hidden: false
  backend_roles:
  - "admin"
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps admin to all_access"

own_index:
  reserved: false
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "*"
  and_backend_roles: []
  description: "Allow full access to an index named like the username"

logstash:
  reserved: false
  hidden: false
  backend_roles:
  - "logstash"
  hosts: []
  users: []
  and_backend_roles: []

readall:
  reserved: true
  hidden: false
  backend_roles:
  - "readall"
  hosts: []
  users: []
  and_backend_roles: []

manage_snapshots:
  reserved: true
  hidden: false
  backend_roles:
  - "snapshotrestore"
  hosts: []
  users: []
  and_backend_roles: []

kibana_server:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "kibanaserver"
  and_backend_roles: []

kibana_user:
  reserved: false
  hidden: false
  backend_roles:
  - "kibanauser"
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps kibanauser to kibana_user"

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "kibanaserver"
  and_backend_roles: []
{{- end }}

{{- define "wazuh.indexer.roles"}}
_meta:
  type: "roles"
  config_version: 2

# Restrict users so they can only view visualization and dashboard on OpenSearchDashboards
kibana_read_only:
  reserved: true

# The security REST API access role is used to assign specific users access to change the security settings through the REST API.
security_rest_api_access:
  reserved: true

security_rest_api_full_access:
  reserved: true
  cluster_permissions:
    - 'restapi:admin/actiongroups'
    - 'restapi:admin/allowlist'
    - 'restapi:admin/config/update'
    - 'restapi:admin/internalusers'
    - 'restapi:admin/nodesdn'
    - 'restapi:admin/roles'
    - 'restapi:admin/rolesmapping'
    - 'restapi:admin/ssl/certs/info'
    - 'restapi:admin/ssl/certs/reload'
    - 'restapi:admin/tenants'

# Allows users to view monitors, destinations and alerts
alerting_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/get'
    - 'cluster:admin/opendistro/alerting/destination/get'
    - 'cluster:admin/opendistro/alerting/monitor/get'
    - 'cluster:admin/opendistro/alerting/monitor/search'
    - 'cluster:admin/opensearch/alerting/findings/get'
    - 'cluster:admin/opensearch/alerting/workflow/get'
    - 'cluster:admin/opensearch/alerting/workflow_alerts/get'

# Allows users to view and acknowledge alerts
alerting_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/alerting/alerts/*'
    - 'cluster:admin/opendistro/alerting/chained_alerts/*'
    - 'cluster:admin/opendistro/alerting/workflow_alerts/*'

# Allows users to use all alerting functionality
alerting_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/alerting/*'
    - 'cluster:admin/opensearch/alerting/*'
    - 'cluster:admin/opensearch/notifications/feature/publish'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to read Anomaly Detection detectors and results
anomaly_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/ad/detector/info'
    - 'cluster:admin/opendistro/ad/detector/search'
    - 'cluster:admin/opendistro/ad/detectors/get'
    - 'cluster:admin/opendistro/ad/result/search'
    - 'cluster:admin/opendistro/ad/tasks/search'
    - 'cluster:admin/opendistro/ad/detector/validate'
    - 'cluster:admin/opendistro/ad/result/topAnomalies'

# Allows users to use all Anomaly Detection functionality
anomaly_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opendistro/ad/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'
        - 'indices:admin/aliases/get'
        - 'indices:admin/mappings/get'

# Allow users to execute read only k-NN actions
knn_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/knn_search_model_action'
    - 'cluster:admin/knn_get_model_action'
    - 'cluster:admin/knn_stats_action'

# Allow users to use all k-NN functionality
knn_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/knn_training_model_action'
    - 'cluster:admin/knn_training_job_router_action'
    - 'cluster:admin/knn_training_job_route_decision_info_action'
    - 'cluster:admin/knn_warmup_action'
    - 'cluster:admin/knn_delete_model_action'
    - 'cluster:admin/knn_remove_model_from_cache_action'
    - 'cluster:admin/knn_update_model_graveyard_action'
    - 'cluster:admin/knn_search_model_action'
    - 'cluster:admin/knn_get_model_action'
    - 'cluster:admin/knn_stats_action'

# Allow users to execute read only ip2geo datasource action
ip2geo_datasource_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/geospatial/datasource/get'

# Allow users to use all ip2geo datasource action
ip2geo_datasource_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/geospatial/datasource/*'

# Allows users to read Notebooks
notebooks_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/list'
    - 'cluster:admin/opendistro/notebooks/get'

# Allows users to all Notebooks functionality
notebooks_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/notebooks/create'
    - 'cluster:admin/opendistro/notebooks/update'
    - 'cluster:admin/opendistro/notebooks/delete'
    - 'cluster:admin/opendistro/notebooks/get'
    - 'cluster:admin/opendistro/notebooks/list'

# Allows users to read observability objects
observability_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/observability/get'

# Allows users to all Observability functionality
observability_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/observability/create'
    - 'cluster:admin/opensearch/observability/update'
    - 'cluster:admin/opensearch/observability/delete'
    - 'cluster:admin/opensearch/observability/get'

# Allows users to all PPL functionality
ppl_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/ppl'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/mappings/get'
        - 'indices:data/read/search*'
        - 'indices:monitor/settings/get'

# Allows users to read and download Reports
reports_instances_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to read and download Reports and Report-definitions
reports_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to all Reports functionality
reports_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/reports/definition/create'
    - 'cluster:admin/opendistro/reports/definition/update'
    - 'cluster:admin/opendistro/reports/definition/on_demand'
    - 'cluster:admin/opendistro/reports/definition/delete'
    - 'cluster:admin/opendistro/reports/definition/get'
    - 'cluster:admin/opendistro/reports/definition/list'
    - 'cluster:admin/opendistro/reports/instance/list'
    - 'cluster:admin/opendistro/reports/instance/get'
    - 'cluster:admin/opendistro/reports/menu/download'

# Allows users to use all asynchronous-search functionality
asynchronous_search_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:data/read/search*'

# Allows users to read stored asynchronous-search results
asynchronous_search_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opendistro/asynchronous_search/get'

# Allows user to use all index_management actions - ism policies, rollups, transforms
index_management_full_access:
  reserved: true
  cluster_permissions:
    - "cluster:admin/opendistro/ism/*"
    - "cluster:admin/opendistro/rollup/*"
    - "cluster:admin/opendistro/transform/*"
    - "cluster:admin/opensearch/controlcenter/lron/*"
    - "cluster:admin/opensearch/notifications/channels/get"
    - "cluster:admin/opensearch/notifications/feature/publish"
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/opensearch/ism/*'

# Allows users to use all cross cluster replication functionality at leader cluster
cross_cluster_replication_leader_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - "indices:admin/plugins/replication/index/setup/validate"
        - "indices:data/read/plugins/replication/changes"
        - "indices:data/read/plugins/replication/file_chunk"

# Allows users to use all cross cluster replication functionality at follower cluster
cross_cluster_replication_follower_full_access:
  reserved: true
  cluster_permissions:
    - "cluster:admin/plugins/replication/autofollow/update"
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - "indices:admin/plugins/replication/index/setup/validate"
        - "indices:data/write/plugins/replication/changes"
        - "indices:admin/plugins/replication/index/start"
        - "indices:admin/plugins/replication/index/pause"
        - "indices:admin/plugins/replication/index/resume"
        - "indices:admin/plugins/replication/index/stop"
        - "indices:admin/plugins/replication/index/update"
        - "indices:admin/plugins/replication/index/status_check"

# Allows users to use all cross cluster search functionality at remote cluster
cross_cluster_search_remote_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/shards/search_shards'
        - 'indices:data/read/search'

# Allow users to read ML stats/models/tasks
ml_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/ml/stats/nodes'
    - 'cluster:admin/opensearch/ml/model_groups/search'
    - 'cluster:admin/opensearch/ml/models/get'
    - 'cluster:admin/opensearch/ml/models/search'
    - 'cluster:admin/opensearch/ml/tasks/get'
    - 'cluster:admin/opensearch/ml/tasks/search'

# Allows users to use all ML functionality
ml_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster_monitor'
    - 'cluster:admin/opensearch/ml/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices_monitor'

# Allows users to use all Notifications functionality
notifications_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/notifications/*'

# Allows users to read Notifications config/channels
notifications_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/notifications/configs/get'
    - 'cluster:admin/opensearch/notifications/features'
    - 'cluster:admin/opensearch/notifications/channels/get'

# Allows users to use all snapshot management functionality
snapshot_management_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/snapshot_management/*'
    - 'cluster:admin/opensearch/notifications/feature/publish'
    - 'cluster:admin/repository/*'
    - 'cluster:admin/snapshot/*'

# Allows users to see snapshots, repositories, and snapshot management policies
snapshot_management_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/snapshot_management/policy/get'
    - 'cluster:admin/opensearch/snapshot_management/policy/search'
    - 'cluster:admin/opensearch/snapshot_management/policy/explain'
    - 'cluster:admin/repository/get'
    - 'cluster:admin/snapshot/get'

# Allows user to use point in time functionality
point_in_time_full_access:
  reserved: true
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'manage_point_in_time'

# Allows users to see security analytics detectors and others
security_analytics_read_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/get'
    - 'cluster:admin/opensearch/securityanalytics/correlations/findings'
    - 'cluster:admin/opensearch/securityanalytics/correlations/list'
    - 'cluster:admin/opensearch/securityanalytics/detector/get'
    - 'cluster:admin/opensearch/securityanalytics/detector/search'
    - 'cluster:admin/opensearch/securityanalytics/findings/get'
    - 'cluster:admin/opensearch/securityanalytics/mapping/get'
    - 'cluster:admin/opensearch/securityanalytics/mapping/view/get'
    - 'cluster:admin/opensearch/securityanalytics/rule/get'
    - 'cluster:admin/opensearch/securityanalytics/rule/search'

# Allows users to use all security analytics functionality
security_analytics_full_access:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/*'
    - 'cluster:admin/opensearch/securityanalytics/correlations/*'
    - 'cluster:admin/opensearch/securityanalytics/detector/*'
    - 'cluster:admin/opensearch/securityanalytics/findings/*'
    - 'cluster:admin/opensearch/securityanalytics/mapping/*'
    - 'cluster:admin/opensearch/securityanalytics/rule/*'
  index_permissions:
    - index_patterns:
        - '*'
      allowed_actions:
        - 'indices:admin/mapping/put'
        - 'indices:admin/mappings/get'

# Allows users to view and acknowledge alerts
security_analytics_ack_alerts:
  reserved: true
  cluster_permissions:
    - 'cluster:admin/opensearch/securityanalytics/alerts/*'

# Wazuh monitoring and statistics index permissions
manage_wazuh_index:
  reserved: true
  hidden: false
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "read"
    - "delete"
    - "manage"
    - "index"
  tenant_permissions: []
  static: false
{{- end }}

{{- define "wazuh.indexer.securityConfig"}}
---

# This is the main OpenSearch Security configuration file where authentication
# and authorization is defined.
#
# You need to configure at least one authentication domain in the authc of this file.
# An authentication domain is responsible for extracting the user credentials from
# the request and for validating them against an authentication backend like Active Directory for example.
#
# If more than one authentication domain is configured the first one which succeeds wins.
# If all authentication domains fail then the request is unauthenticated.
# In this case an exception is thrown and/or the HTTP status is set to 401.
#
# After authentication authorization (authz) will be applied. There can be zero or more authorizers which collect
# the roles from a given backend for the authenticated user.
#
# Both, authc and auth can be enabled/disabled separately for REST and TRANSPORT layer. Default is true for both.
#        http_enabled: true
#        transport_enabled: true
#
# For HTTP it is possible to allow anonymous authentication. If that is the case then the HTTP authenticators try to
# find user credentials in the HTTP request. If credentials are found then the user gets regularly authenticated.
# If none can be found the user will be authenticated as an "anonymous" user. This user has always the username "anonymous"
# and one role named "anonymous_backendrole".
# If you enable anonymous authentication all HTTP authenticators will not challenge.
#
#
# Note: If you define more than one HTTP authenticators make sure to put non-challenging authenticators like "proxy" or "clientcert"
# first and the challenging one last.
# Because it's not possible to challenge a client with two different authentication methods (for example
# Kerberos and Basic) only one can have the challenge flag set to true. You can cope with this situation
# by using pre-authentication, e.g. sending a HTTP Basic authentication header in the request.
#
# Default value of the challenge flag is true.
#
#
# HTTP
#   basic (challenging)
#   proxy (not challenging, needs xff)
#   kerberos (challenging)
#   clientcert (not challenging, needs https)
#   jwt (not challenging)
#   host (not challenging) #DEPRECATED, will be removed in a future version.
#                          host based authentication is configurable in roles_mapping

# Authc
#   internal
#   noop
#   ldap

# Authz
#   ldap
#   noop



_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    # Set filtered_alias_mode to 'disallow' to forbid more than 2 filtered aliases per index
    # Set filtered_alias_mode to 'warn' to allow more than 2 filtered aliases per index but warns about it (default)
    # Set filtered_alias_mode to 'nowarn' to allow more than 2 filtered aliases per index silently
    #filtered_alias_mode: warn
    #do_not_fail_on_forbidden: false
    #kibana:
    # Kibana multitenancy
    #multitenancy_enabled: true
    #private_tenant_enabled: true
    #default_tenant: ""
    #server_username: kibanaserver
    #index: '.kibana'
    http:
      anonymous_auth_enabled: false
      xff:
        enabled: false
        internalProxies: '192\.168\.0\.10|192\.168\.0\.11' # regex pattern
        #internalProxies: '.*' # trust all internal proxies, regex pattern
        #remoteIpHeader:  'x-forwarded-for'
        ###### see https://docs.oracle.com/javase/7/docs/api/java/util/regex/Pattern.html for regex help
        ###### more information about XFF https://en.wikipedia.org/wiki/X-Forwarded-For
        ###### and here https://tools.ietf.org/html/rfc7239
        ###### and https://tomcat.apache.org/tomcat-8.0-doc/config/valve.html#Remote_IP_Valve
    authc:
      kerberos_auth_domain:
        http_enabled: false
        transport_enabled: false
        order: 6
        http_authenticator:
          type: kerberos
          challenge: true
          config:
            # If true a lot of kerberos/security related debugging output will be logged to standard out
            krb_debug: false
            # If true then the realm will be stripped from the user name
            strip_realm_from_principal: true
        authentication_backend:
          type: noop
      basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 4
        http_authenticator:
          type: basic
          challenge: true
        authentication_backend:
          type: intern
      proxy_auth_domain:
        description: "Authenticate via proxy"
        http_enabled: false
        transport_enabled: false
        order: 3
        http_authenticator:
          type: proxy
          challenge: false
          config:
            user_header: "x-proxy-user"
            roles_header: "x-proxy-roles"
        authentication_backend:
          type: noop
      jwt_auth_domain:
        description: "Authenticate via Json Web Token"
        http_enabled: false
        transport_enabled: false
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: "base64 encoded HMAC key or public RSA/ECDSA pem key"
            jwt_header: "Authorization"
            jwt_url_parameter: null
            jwt_clock_skew_tolerance_seconds: 30
            roles_key: null
            subject_key: null
        authentication_backend:
          type: noop
      clientcert_auth_domain:
        description: "Authenticate via SSL client certificates"
        http_enabled: false
        transport_enabled: false
        order: 2
        http_authenticator:
          type: clientcert
          config:
            username_attribute: cn #optional, if omitted DN becomes username
          challenge: false
        authentication_backend:
          type: noop
      ldap:
        description: "Authenticate via LDAP or Active Directory"
        http_enabled: false
        transport_enabled: false
        order: 5
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          # LDAP authentication backend (authenticate users against a LDAP or Active Directory)
          type: ldap
          config:
            # enable ldaps
            enable_ssl: false
            # enable start tls, enable_ssl should be false
            enable_start_tls: false
            # send client certificate
            enable_ssl_client_auth: false
            # verify ldap hostname
            verify_hostnames: true
            hosts:
            - localhost:8389
            bind_dn: null
            password: null
            userbase: 'ou=people,dc=example,dc=com'
            # Filter to search for users (currently in the whole subtree beneath userbase)
            # {0} is substituted with the username
            usersearch: '(sAMAccountName={0})'
            # Use this attribute from the user as username (if not set then DN is used)
            username_attribute: null
    authz:
      roles_from_myldap:
        description: "Authorize via LDAP or Active Directory"
        http_enabled: false
        transport_enabled: false
        authorization_backend:
          # LDAP authorization backend (gather roles from a LDAP or Active Directory, you have to configure the above LDAP authentication backend settings too)
          type: ldap
          config:
            # enable ldaps
            enable_ssl: false
            # enable start tls, enable_ssl should be false
            enable_start_tls: false
            # send client certificate
            enable_ssl_client_auth: false
            # verify ldap hostname
            verify_hostnames: true
            hosts:
            - localhost:8389
            bind_dn: null
            password: null
            rolebase: 'ou=groups,dc=example,dc=com'
            # Filter to search for roles (currently in the whole subtree beneath rolebase)
            # {0} is substituted with the DN of the user
            # {1} is substituted with the username
            # {2} is substituted with an attribute value from user's directory entry, of the authenticated user. Use userroleattribute to specify the name of the attribute
            rolesearch: '(member={0})'
            # Specify the name of the attribute which value should be substituted with {2} above
            userroleattribute: null
            # Roles as an attribute of the user entry
            userrolename: disabled
            #userrolename: memberOf
            # The attribute in a role entry containing the name of that role, Default is "name".
            # Can also be "dn" to use the full DN as rolename.
            rolename: cn
            # Resolve nested roles transitive (roles which are members of other roles and so on ...)
            resolve_nested_roles: true
            userbase: 'ou=people,dc=example,dc=com'
            # Filter to search for users (currently in the whole subtree beneath userbase)
            # {0} is substituted with the username
            usersearch: '(uid={0})'
            # Skip users matching a user name, a wildcard or a regex pattern
            #skip_users:
            #  - 'cn=Michael Jackson,ou*people,o=TEST'
            #  - '/\S*/'
      roles_from_another_ldap:
        description: "Authorize via another Active Directory"
        http_enabled: false
        transport_enabled: false
        authorization_backend:
          type: ldap
          #config goes here ...
  #    auth_failure_listeners:
  #      ip_rate_limiting:
  #        type: ip
  #        allowed_tries: 10
  #        time_window_seconds: 3600
  #        block_expiry_seconds: 600
  #        max_blocked_clients: 100000
  #        max_tracked_clients: 100000
  #      internal_authentication_backend_limiting:
  #        type: username
  #        authentication_backend: intern
  #        allowed_tries: 10
  #        time_window_seconds: 3600
  #        block_expiry_seconds: 600
  #        max_blocked_clients: 100000
  #        max_tracked_clients: 100000
{{- end }}
