package org.apereo.portal.security.provider.azure.web;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.provider.azure.helper.AuthTtlException;
import org.apereo.portal.security.provider.azure.helper.AzureSSOAuthHelper;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletResponse;

@Slf4j
public class AzureSSORedirectFilter extends AzureSSOBaseFilter {

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.homePage}")
    private String homePage;

    @Autowired
    private AzureSSOAuthHelper authHelper;

    public AzureSSORedirectFilter() {
        super.setLogger(log);
    }

    @Override
    protected boolean filterRequest(IdentityContextAdapter adapter) {
        log.info("redirect for SSO filterRequest()");
        try {
            authHelper.processAADCallback(adapter);
            log.info("redirecting to home page.");
            adapter.redirectUser(String.format("%s/%s", homePage, "Login"));
            log.info("clearning state and nonce from sso data");
            adapter.getContext().setStateAndNonce(null, null);
            return false; // stop chain
        } catch (AuthTtlException e) {
            log.error("Error signing into Azure SSO", e);
            adapter.getResponse().setStatus(HttpServletResponse.SC_REQUEST_TIMEOUT);
        } catch (Exception e) {
            log.error("Error signing into Azure SSO", e);
        }
        return true;
    }
}
