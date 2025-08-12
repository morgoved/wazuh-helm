## SSO with Dex Server ( Github ID Provider )
### This example shows how to configure Wazuh with SSO using a Dex server, where the Dex server uses GitHub as the IdP
```yaml
indexer:
  networkPolicy:
    extraEgresses:
      ## Allow egress to port 443 for the dex server DNS
      - ports:
          - port: 443
            protocol: TCP
dashboard:
  networkPolicy:
    extraEgresses:
      ## Allow egress to port 443 for the dex server DNS
      - ports:
          - port: 443
            protocol: TCP
  ## This has to be enabled for the Dex Logout to work
  ## Else wazuh dashboard will automatically perform login with SSO in the Home Page
  basicAuth:
    enabled: true
  sso:
    oidc:
      enabled: true
      primary: true
      url: "https://github-dex.example.com/dex/.well-known/openid-configuration"
      ## Query parameters below is required for the logout to work
      ## client_id: Wazuh doesn't automatically inject the client_id into the logoutUrl parameter and it's required by Dex
      ## redirect_uri: Dex only accepts the encoded version of the redirect_uri, not post_logout_redirect_uri like the one injected by Wazuh
      logoutUrl: "https://github-dex.example.com/dex/auth/logout?client_id=${OPENSEARCH_OIDC_CLIENT_ID}&redirect_uri=https%3A%2F%2Fwazuh.example.com"
      baseRedirectUrl: "https://wazuh.example.com"
      existingSecret: "wazuh-dex-client"
      clientIdKey: "WAZUH_CLIENT_ID"
      clientSecretKey: "WAZUH_CLIENT_SECRET"
      scope: "openid profile email groups"
      config:
        subjectKey: "email"
        rolesKey: "groups"
      ## Mapping github teams to roles
      roleMappings:
        allAccess:
          backendRoles:
            - "org_name:role_A"
            - "org_name:role_B"
        kibanaUser:
          backendRoles:
            - "org_name:role_c"
            - "org_name:role_d"
            - "org_name:role_e"
  ingress:
    enabled: true
    className: "nginx-internal"
    host: "wazuh.example.com"
    annotations:
      external-dns.alpha.kubernetes.io/hostname: "wazuh.example.com"
    tls:
      - hosts:
          - wazuh.example.com
```