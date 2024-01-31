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
import org.apereo.portal.security.ISecurityContextFactory;
import org.apereo.services.persondir.support.IAdditionalDescriptors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AzureSSOSecurityContextFactory implements ISecurityContextFactory {

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContextFactory.enabled:false}")
    private boolean enabled;

    @Autowired
    @Qualifier("sessionScopeAdditionalDescriptors")
    private IAdditionalDescriptors additionalDescriptors;

    @Override
    public String getName() {
        return "azureSSO";
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public AzureSSOSecurityContext getSecurityContext() {
        log.debug("return new AzureSSOSecurityContext object");
        return new AzureSSOSecurityContext(additionalDescriptors);
    }
}
