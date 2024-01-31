/**
 * Licensed to Apereo under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright ownership. Apereo
 * licenses this file to you under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the License at the
 * following location:
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apereo.portal.security.provider.azure;

import lombok.extern.slf4j.Slf4j;
import org.apereo.portal.security.ISecurityContext;
import org.apereo.portal.security.PortalSecurityException;
import org.apereo.portal.security.provider.ChainingSecurityContext;
import org.apereo.portal.security.provider.azure.helper.IdentityContextData;
import org.apereo.services.persondir.support.IAdditionalDescriptors;
import org.springframework.beans.factory.annotation.Value;

import java.util.Collections;
import java.util.List;

/**
 * A security context for Azure SSO.
 */
@Slf4j
class AzureSSOSecurityContext extends ChainingSecurityContext implements ISecurityContext {

    private static final int AZURESSOSECURITYAUTHTYPE = 0xFF08;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.clientID}")
    private String clientID;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.tenantID}")
    private String tenantID;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.secret}")
    private String secret;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.scopes}")
    private String scopes;

    /* target of user attributes */
    private final IAdditionalDescriptors additionalDescriptors;

    private IdentityContextData data;

    /*package*/ AzureSSOSecurityContext(IAdditionalDescriptors additionalDescriptors) {
        this.additionalDescriptors = additionalDescriptors;
    }

    @Override
    public int getAuthType() {
        return AZURESSOSECURITYAUTHTYPE;
    }

    @Override
    public synchronized void authenticate() throws PortalSecurityException {
        log.info("Authenticating user via Azure SSO");
        this.isauth = false;
        this.data = AzureSSODataHolder.data.get();

        final String username = getUsername();
        if (username != null) {
            log.debug("Azure SSO data found for {}", username);
            // Set the UID for the principal
            this.myPrincipal.setUID(username);

            // Check that the principal UID matches the remote user
            final String newUid = this.myPrincipal.getUID();

            if (username.equals(newUid)) {
                log.info("Azure Security Context authenticated {}", username);
                this.isauth = true;
                captureUserAttributes();
                logMoreSsoDetails();
            } else {
                log.warn("Attempted to set portal principal username to {} but uid is instead set to {}", username, newUid);
            }
        } else {
            log.info("Authentication failed. Azure SSO data not set for {}", this.myPrincipal.getUID());
        }

        this.myAdditionalDescriptor = null;
        super.authenticate();
        log.info("Finished Azure SSO Authentication");
    }

    private String getUsername() {
        if (data == null) {
            log.warn("data is null");
            return null;
        }
        String id = getDerivedUid();
        if (id != null) {
            log.debug("derived username = {}", id);
            return id;
        } else {
            log.debug("no upn, falling back to {}", data.getUsername());
            return data.getUsername();
        }
    }

    private void captureUserAttributes() {
        log.info("Capturing user attributes from Azure claims");
        this.data.getIdTokenClaims().forEach((k,v) -> {
            log.debug("claim: {} -> {}", k, v.toString());
            setUserAttribute(k, v);
        });
        setUserAttribute("uid", getDerivedUid());
        addMappedAttribute("displayName", "name");
        log.info("Finished capturing user attributes from Azure claims");
    }

    private String getDerivedUid() {
        assert(data != null);
        Object rawUpn = data.getIdTokenClaims().get("upn");
        if (rawUpn == null) {
            log.warn("no upn for {}", data.getUsername());
            return null;
        }
        String upn = String.valueOf(rawUpn);
        // this approach handles an upn that doesn't have an @
        String uid = upn.split("@")[0];
        log.debug("uid = {}", uid);
        return uid;
    }

    private void addMappedAttribute(String uPortalKey, String azureKey) {
        assert(data != null);
        Object value = data.getIdTokenClaims().get(azureKey);
        if (value == null) {
            log.warn("no value for {}", azureKey);
            return;
        }
        log.debug("mapping {} -> {} = {}", azureKey, uPortalKey, value);
        setUserAttribute(uPortalKey, value);
    }

    private void setUserAttribute(String key, Object value) {
        if (key == null || value == null) {
            log.warn("user attribute key nor value may be null: {} = {}", key, value);
            return;
        }
        List<Object> val = (value instanceof List) ? (List<Object>) value : Collections.singletonList(value);
        additionalDescriptors.setAttributeValues(key, val);
    }

    private void logMoreSsoDetails() {
        log.info("Account = {}", data.getAccount().toString());
        log.debug("Roles: {}", data.getRoles().toString());
        log.debug("Groups: {}", data.getGroups().toString());
    }
}
