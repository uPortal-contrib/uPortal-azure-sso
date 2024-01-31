// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package org.apereo.portal.security.provider.azure.helper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Implement this so that AuthHelper can be customized to your needs!
 * This Sample project implements this in IdentityContextAdapterServlet.java
 * MUST BE INSTANTIATED ONCE PER REQUEST IN WEB APPS / WEB APIs before passing to AuthHelper
 */
public interface IdentityContextAdapter {
    public void setContext(IdentityContextData context);
    public IdentityContextData getContext();
    public HttpServletRequest getRequest();
    public HttpServletResponse getResponse();
    public String getLocation();
    public void redirectUser(String location) throws IOException;
    public String getParameter(String parameterName);
}
