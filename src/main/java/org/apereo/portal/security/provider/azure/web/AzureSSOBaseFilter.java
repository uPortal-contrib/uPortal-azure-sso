package org.apereo.portal.security.provider.azure.web;

import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapterImpl;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

abstract class AzureSSOBaseFilter implements Filter {

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContextFactory.enabled:false}")
    private boolean enabled;

    private Logger log;

    protected void setLogger(Logger logger) {
        this.log = logger;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        log.debug("Azure SSO filter init()");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        if (enabled) {
            log.debug("Azure SSO enabled");
            HttpServletRequest request = (HttpServletRequest) servletRequest;
            HttpServletResponse response = (HttpServletResponse) servletResponse;

            log.debug("Creating IdentityContextAdapter");
            IdentityContextAdapter context = new IdentityContextAdapterImpl(request, response);
            log.debug("Calling abstract filterRequest()");
            boolean cont = filterRequest(context);
            log.debug("return from filterRequest() -- continue? {}", cont);
            if (!cont) {
                log.debug("location = {}", response.getHeader("location"));
                log.debug("flushing response buffer");
                response.flushBuffer();
                return;
            }
        } else {
            log.debug("Azure SSO disabled");
        }
        // if disabled, silent signin, or error; continue
        log.debug("continue with other filters...");
        filterChain.doFilter(servletRequest, servletResponse);
    }

    abstract protected boolean filterRequest(IdentityContextAdapter adapter);

    @Override
    public void destroy() {
        log.debug("Azure SSO filter destroy()");
    }
}
