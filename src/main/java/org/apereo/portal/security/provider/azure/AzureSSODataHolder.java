package org.apereo.portal.security.provider.azure;

import org.apereo.portal.security.provider.azure.helper.IdentityContextData;

/**
 * Static {@code ThreadLocal<IdentityContextData} for passing the SSO data to classes that
 * do not have access to web objects (i.e. {@code HttpSession}), such as the security context classes.
 */
public class AzureSSODataHolder {

    /* no need to and getters or setters so make this public */
    public static final ThreadLocal<IdentityContextData> data = new ThreadLocal<IdentityContextData>();
}
