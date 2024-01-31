// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package org.apereo.portal.security.provider.azure.helper;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.provider.azure.AzureSSODataHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionActivationListener;
import javax.servlet.http.HttpSessionEvent;
import java.io.IOException;

/**
 * Implementation of IdentityContextAdapter for AuthHelper for use with Java
 * HttpServletRequests/Responses MUST BE INSTANTIATED ONCE PER REQUEST IN WEB
 * APPS / WEB APIs before passing to AuthHelper
 */
@Slf4j
public class IdentityContextAdapterImpl implements IdentityContextAdapter, HttpSessionActivationListener {
    private HttpSession session = null;
    private IdentityContextData context = null;
    private HttpServletRequest request = null;
    private HttpServletResponse response = null;
    private String location = null;
    private String sessionParam = "msalAuth";

    public IdentityContextAdapterImpl(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.session = request.getSession();
        this.response = response;
    }

    public void setSessionParam(String sessionParam) {
        assert(sessionParam != null && !sessionParam.isEmpty());
        this.sessionParam = sessionParam;
    }

    // load from session on session activation
    @Override
    public void sessionDidActivate(HttpSessionEvent se) {
        log.info("sessionDidActivate()");
        this.session = se.getSession();
        loadContext();
    }

    // save to session on session passivation
    @Override
    public void sessionWillPassivate(HttpSessionEvent se) {
        log.info("sessionWillPasssivate()");
        this.session = se.getSession();
        saveContext();
    }

    public void saveContext() {
        log.info("saveContext()");
        if (this.context == null)
            this.context = new IdentityContextData();

        this.session.setAttribute(sessionParam, context);
        AzureSSODataHolder.data.set(context);
    }

    public void loadContext() {
        log.info("loadContext()");
        this.context = (IdentityContextData) session.getAttribute(sessionParam);
        if (this.context == null) {
            saveContext();
        } else {
            AzureSSODataHolder.data.set(context);
        }
    }

    @Override
    public IdentityContextData getContext() {
        loadContext();
        return this.context;
    }

    @Override
    public HttpServletRequest getRequest() {
        return request;
    }

    @Override
    public HttpServletResponse getResponse() {
        return response;
    }

    @Override
    public String getLocation() {
        return location;
    }

    @Override
    public void setContext(IdentityContextData context) {
        this.context = context;
        saveContext();
    }

    @Override
    public void redirectUser(String location) throws IOException {
        log.info("Redirecting user to {}", location);
        this.location = location;
        this.response.sendRedirect(location);
        this.response.flushBuffer();
    }

    @Override
    public String getParameter(String parameterName) {
        return this.request.getParameter(parameterName);
    }

}
