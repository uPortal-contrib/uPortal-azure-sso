package org.apereo.portal.security.provider.azure.web;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.provider.azure.helper.AzureSSOAuthHelper;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.apereo.portal.security.provider.azure.helper.IdentityContextData;
import org.springframework.beans.factory.annotation.Autowired;

@Slf4j
public class AzureSSOSignInFilter extends AzureSSOBaseFilter {

    @Autowired
    private AzureSSOAuthHelper authHelper;

    public AzureSSOSignInFilter() {
        super.setLogger(log);
    }

    @Override
    protected boolean filterRequest(IdentityContextAdapter adapter) {
        log.info("Sign in filterRequest()");
        log.debug(adapter.getRequest().getServletPath());
        String backdoorUser = adapter.getRequest().getParameter("userName");
        if (backdoorUser != null) {
            log.info("local login for userName = {}", backdoorUser);
            return true;
        }
        IdentityContextData context = adapter.getContext();
        if (context != null && context.getAuthenticated()) {
            log.info("signed in already -- no need to redirect to sign in");
            return true;
        }
        log.info("Azure SSO login attempt");
        try {
            authHelper.signIn(adapter);
            return false; // stop chain
        } catch (Exception e) {
            log.error("Error signing into Azure SSO", e);
        }
        return true;
    }
}
