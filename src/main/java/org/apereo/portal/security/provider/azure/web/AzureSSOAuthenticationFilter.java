package org.apereo.portal.security.provider.azure.web;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.provider.azure.AzureSSODataHolder;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.apereo.portal.security.provider.azure.helper.IdentityContextData;

@Slf4j
public class AzureSSOAuthenticationFilter extends AzureSSOBaseFilter {

    public AzureSSOAuthenticationFilter() {
        super.setLogger(log);
    }

    @Override
    protected boolean filterRequest(IdentityContextAdapter adapter) {
        log.info("enter filterRequest()");
        log.debug(adapter.getRequest().getServletPath());
        IdentityContextData context = adapter.getContext(); // main effort is adding data object to session and holder
        if (context == null) {
            log.info("no identityContextData");
            return true;
        }
        log.debug("identityContextData = {}", context);
        log.debug("local thread data = {}", AzureSSODataHolder.data.get());
        return true;
    }
}
