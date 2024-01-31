// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


package org.apereo.portal.security.provider.azure.helper;

/*
Required exception class for using AuthHelper.java
*/

public class AuthTtlException extends AuthException {
    public AuthTtlException(String message) {
        super(message);
    }
}
