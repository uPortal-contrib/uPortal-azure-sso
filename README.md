# uPortal-azure-sso
Azure SSO for uPortal

Initially this project will not be provided as a dependency. Rather, this code should be directly added to uPortal-start.
Our usual recommendation is to create a custom/ folder in uPortal-start for custom code.

## Adding Azure SSO to uPortal Project
There are four steps to add this to your portal.
1. Copy src/ and build.gradle into uPortal-start/custom/azure-sso/ or similar location
2. Copy the Custom:AzureSSO section of gradle.properties into uPortal-start/gradle.properties
3. Add `include 'custom:azure-sso'` to settings.gradle
4. Add `compile project(':custom:azure-sso')` to uPortal-start/overlays/uPortal/build.gradle in the first dependencies section

## Configuring uPortal to use Azure SSO
The following configuration should be added to `etc/portal/uPortal.properties`
in the Authentication section of that file:

```properties
##
## Azure SSO Configuration
##
org.apereo.portal.security.provider.azure.AzureSSOSecurityContextFactory.enabled=true
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.clientID=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.tenantID=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.secret=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.homePage=${portal.protocol}://${portal.server}${portal.context}
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.redirectEndpoint=/auth/redirect
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.scopes=openid profile offline_access
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.azureLogin=https://login.microsoftonline.com/
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.signOutEndpoint=/oauth2/v2.0/logout/
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.postSignOutFragment=?post_logout_redirect_uri=
```

Spring Beans Needed In `overridesContext.xml`

```xml

    <!-- replace url encoder / login URL generator with ours -->
    <bean name="casRefUrlEncoder" class="org.apereo.portal.security.provider.azure.web.AzureSSORefUrlEncoder" />

    <!-- filters to manage Azure SSO -->
    <bean name="azureSSOAuthenticationFilter" class="org.apereo.portal.security.provider.azure.web.AzureSSOAuthenticationFilter" />
    <bean name="azureSSORedirectFilter" class="org.apereo.portal.security.provider.azure.web.AzureSSORedirectFilter" />
    <!--
    <bean name="azureSSOSignInFilter" class="org.apereo.portal.security.provider.azure.web.AzureSSOSignInFilter" />
    -->
    <bean name="azureSSOSignOutFilter" class="org.apereo.portal.security.provider.azure.web.AzureSSOSignOutFilter" />

```

Filters Needed In `web.xml`
Recommend adding these after the `corsFilter` filter for consistency, but order is not important:
```xml
    <filter>
        <filter-name>azureSSOAuthenticationFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>

    <filter>
        <filter-name>azureSSORedirectFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>
    <filter>
        <filter-name>azureSSOSignOutFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter>
```

Recommend adding filter mappings after `courseFilter` filter-mapping -- order is important here:
```xml
    <filter-mapping>
        <filter-name>azureSSOAuthenticationFilter</filter-name>
        <url-pattern>/index.jsp</url-pattern>
        <url-pattern>*.uP</url-pattern>
        <url-pattern>/f/*</url-pattern>
        <url-pattern>/p/*</url-pattern>
        <url-pattern>/Login</url-pattern>
        <url-pattern>/auth/redirect</url-pattern>
        <url-pattern>/Logout</url-pattern>
    </filter-mapping>

    <filter-mapping>
        <filter-name>azureSSORedirectFilter</filter-name>
        <url-pattern>/auth/redirect</url-pattern>
    </filter-mapping>

    <filter-mapping>
        <filter-name>azureSSOSignOutFilter</filter-name>
        <url-pattern>/Logout</url-pattern>
    </filter-mapping>
```

## Azure SSO Config Details

The Web Redirect URI is the service URL plus `/uPortal/auth/redirect`.
The Front-channel logout URL is the service URL plus `/uPortal/Logout`.
