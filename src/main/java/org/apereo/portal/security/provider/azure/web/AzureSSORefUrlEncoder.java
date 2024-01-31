package org.apereo.portal.security.provider.azure.web;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.mvc.LoginController;
import org.apereo.portal.security.provider.azure.AzureSSODataHolder;
import org.apereo.portal.security.provider.azure.helper.AzureSSOAuthHelper;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapter;
import org.apereo.portal.security.provider.azure.helper.IdentityContextAdapterImpl;
import org.apereo.portal.security.provider.azure.helper.IdentityContextData;
import org.apereo.portal.url.LoginRefUrlEncoder;
import org.apereo.portal.url.UrlAuthCustomizerRegistry;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@Slf4j
public class AzureSSORefUrlEncoder implements LoginRefUrlEncoder {

    @Autowired
    private AzureSSOAuthHelper authHelper;

    @Autowired
    private UrlAuthCustomizerRegistry urlCustomizer;

    public String getLoginUrl(HttpServletRequest httpServletRequest) {
        log.info("getLoginUrl");
        IdentityContextAdapter adapter = new IdentityContextAdapterImpl(httpServletRequest, null);
        IdentityContextData contextData = adapter.getContext();
        if (contextData == null) {
            // shouldn't happen as the getContext() above will create a context if missing
            log.warn("missing identity context data");
            return null;
        }
        log.debug("identityContextData = {}", contextData);
        log.debug("local thread data = {}", AzureSSODataHolder.data.get());
        try {
            String url = authHelper.buildAuthorizeUrl(adapter);
            log.debug("LoginRedirect url = {}", url);
            return url;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String getCasLoginUrl(final HttpServletRequest request) {
        return urlCustomizer.customizeUrl(request, this.getLoginUrl(request));
    }

    @Override
    public String encodeLoginAndRefUrl(HttpServletRequest request) throws UnsupportedEncodingException {
        final String requestEncoding = request.getCharacterEncoding();
        final StringBuilder loginRedirect = new StringBuilder();

        loginRedirect.append(this.getLoginUrl(request));
        loginRedirect.append(URLEncoder.encode("?", requestEncoding));
        loginRedirect.append(
                URLEncoder.encode(LoginController.REFERER_URL_PARAM + "=", requestEncoding));

        loginRedirect.append(URLEncoder.encode(request.getRequestURI(), requestEncoding));

        final String queryString = request.getQueryString();
        if (queryString != null) {
            String firstEncoding = URLEncoder.encode("?" + queryString, requestEncoding);
            loginRedirect.append(URLEncoder.encode(firstEncoding, requestEncoding));
        }

        return urlCustomizer.customizeUrl(request, loginRedirect.toString());
    }
}
