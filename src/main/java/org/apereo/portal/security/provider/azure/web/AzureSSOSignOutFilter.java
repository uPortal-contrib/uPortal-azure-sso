package org.apereo.portal.security.provider.azure.web;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.provider.azure.helper.AzureSSOAuthHelper;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.apereo.portal.security.provider.azure.helper.IdentityContextData;
import org.springframework.beans.factory.annotation.Autowired;

@Slf4j
public class AzureSSOSignOutFilter extends AzureSSOBaseFilter {

    @Autowired
    private AzureSSOAuthHelper authHelper;

    public AzureSSOSignOutFilter() {
        super.setLogger(log);
    }

    @Override
    protected boolean filterRequest(IdentityContextAdapter adapter) {
        log.info("Sign out filterRequest()");
        IdentityContextData context = adapter.getContext();
        if (context == null) {
            log.info("not signed in -- no need to redirect to sign out");
            return true;
        }
        log.info("Azure SSO logout attempt");
        try {
            log.debug("Clearing context from session / holder class");
            adapter.setContext(null);
            //log.debug("call authHelper.signOut()");
            //authHelper.signOut(adapter);
            //return false; // stop chain
        } catch (Exception e) {
            log.error("Error signing out of Azure SSO", e);
        }
        return true;
    }
}
