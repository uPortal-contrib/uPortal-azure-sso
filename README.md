# uPortal-azure-sso
Azure SSO for uPortal

Initially this project will not be provided as a dependency. Rather, this code should be directly added to uPortal-start.
Our usual recommendation is to create a custom/ folder in uPortal-start for custom code.

There are four steps to add this to your portal.
1. Copy src/ and build.gradle into uPortal-start/custom/azure-sso/ or similar location
2. Copy the Custom:AzureSSO section of gradle.properties inot uPortal-start/gradle.properties
3. Add `include 'custom:azure-sso'` to settings.gradle [adjust to your pathing]
4. Add `compile project('custom:azure-sso')` to uPortal-start/overlays/uPortal/build.gradle in the first dependencies section

## Configuring uPortal to use Azure SSO
The following configuration should be added to `etc/portal/uPortal.properties`
in the Authentication section of that file:

```
##
## Azure SSO Configuration
##
org.apereo.portal.security.provider.azure.AzureSSOSecurityContextFactory.enabled=true
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.clientID=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.tenantID=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.secret=
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.homePage=${portal.protocol}://${portal.server}${portal.context}
org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.redirectEndpoint=/Login
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.scopes=openid profile offline_access
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.azureLogin=https://login.microsoftonline.com/
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.signOutEndpoint=/oauth2/v2.0/logout/
#org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.postSignOutFragment=?post_logout_redirect_uri=
```
