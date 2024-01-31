// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package org.apereo.portal.security.provider.azure.helper;

import com.microsoft.aad.msal4j.AuthorizationCodeParameters;
import com.microsoft.aad.msal4j.AuthorizationRequestUrlParameters;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientSecret;
import com.microsoft.aad.msal4j.Prompt;
import com.microsoft.aad.msal4j.ResponseMode;
import com.microsoft.aad.msal4j.SilentParameters;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

/**
 * This class contains almost all of our authentication logic MSAL Java apps
 * using this sample repository's paradigm will require this.
 */
@Component
@Slf4j
public class AzureSSOAuthHelper {

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.clientID}")
    private String clientID;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.tenantID}")
    private String tenantID;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.secret}")
    private String secret;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.scopes:openid profile offline_access}")
    private String scopes;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.azureLogin:https://login.microsoftonline.com/}")
    private String azureLogin;

    private String authority;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.signOutEndpoint:/oauth2/v2.0/logout/}")
    private String signOutEndpoint;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.postSignOutFragment:?post_logout_redirect_uri=}")
    private String postSignOutFragment;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.homePage}")
    private String homePage;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.redirectEndpoint}")
    private String redirectEndpoint;

    private String redirectUri;

    @Value("${org.apereo.portal.security.provider.azure.AzureSSOSecurityContext.ttl:6000}")
    private long ttl;

    @PostConstruct
    public void init() throws Exception {
        authority = String.format("%s%s", azureLogin, tenantID);
        log.debug("authority = {}", authority);
        redirectUri = String.format("%s%s", homePage, redirectEndpoint);
        log.debug("redurectUri = {}", redirectUri);

    }
    public ConfidentialClientApplication getConfidentialClientInstance() throws MalformedURLException {
        ConfidentialClientApplication confClientInstance = null;
        log.info("Getting confidential client instance");
        try {
            final IClientSecret clientSecret = ClientCredentialFactory.createFromSecret(secret);
            confClientInstance = ConfidentialClientApplication.builder(clientID, clientSecret)
                    .authority(authority).build();
        } catch (final Exception ex) {
            log.error("Failed to create Confidential Client Application.");
            throw ex;
        }
        return confClientInstance;
    }

    public void signIn(IdentityContextAdapter contextAdapter) throws AuthException, IOException {
        log.info("sign in init");
        authorize(contextAdapter); // authorize tries to do non-interactive auth first
    }

    public void signOut(IdentityContextAdapter contextAdapter) throws IOException {
        log.info("sign out init");
        redirectToSignOutEndpoint(contextAdapter);
    }

    public void redirectToSignOutEndpoint(IdentityContextAdapter contextAdapter) throws IOException {
        contextAdapter.setContext(null);
        final String redirect = String.format("%s%s%s%s", authority, signOutEndpoint,
                postSignOutFragment, URLEncoder.encode(homePage, "UTF-8"));
        contextAdapter.redirectUser(redirect);
    }

    public void authorize(IdentityContextAdapter contextAdapter) throws IOException, AuthException {

        final IdentityContextData context = contextAdapter.getContext();
        log.info("preparing to authorize");

        if (context.getAccount() != null) {
            log.info("found account in session. trying to silently acquire token...");
            acquireTokenSilently(contextAdapter);
        } else {
            log.info("did not find auth result in session. trying to interactively acquire token...");
            redirectToAuthorizationEndpoint(contextAdapter);
        }
    }

    public void acquireTokenSilently(IdentityContextAdapter contextAdapter)
            throws AuthException {
        final IdentityContextData context = contextAdapter.getContext();

        if (context.getAccount() == null) {
            String message = "Need to have account in session in order to authorize silently";
            log.error(message);
            throw new AuthException(message);
        }
        final SilentParameters parameters = SilentParameters.builder(Collections.singleton(scopes), context.getAccount())
                .build();

        try {
            final ConfidentialClientApplication client = getConfidentialClientInstance();
            client.tokenCache().deserialize(context.getTokenCache());
            log.info("preparing to acquire silently");
            final IAuthenticationResult result = client.acquireTokenSilently(parameters).get();
            log.info("got auth result!");
            if (result != null) {
                log.info("silent auth returned result. attempting to parse and process...");
                context.setAuthResult(result, client.tokenCache().serialize());
                // handle groups overage if it has occurred.
                // optional: see groups sample.
                // you will need aad.scopes=GroupMember.Read.All in your config file.
                // uncomment the following method call if this is relevant to you:
                // handleGroupsOverage(contextAdapter);
                log.info("silent auth success!");
            } else {
                log.info("silent auth returned null result! redirecting to authorize with code");
                throw new AuthException("Unexpected Null result when attempting to acquire token silently.");
            }
        } catch (final Exception ex) {
            String message = String.format("Failed to acquire token silently:%n %s", ex.getMessage());
            log.error(message);
            log.debug(Arrays.toString(ex.getStackTrace()));
            throw new AuthException(message);
        }
    }

    private void redirectToAuthorizationEndpoint(IdentityContextAdapter contextAdapter) throws IOException {
        final String authorizeUrl = buildAuthorizeUrl(contextAdapter);
        contextAdapter.redirectUser(authorizeUrl);
    }

    public String buildAuthorizeUrl(IdentityContextAdapter contextAdapter) throws IOException {
        final IdentityContextData context = contextAdapter.getContext();
        final String state = context.getState() != null? context.getState() : UUID.randomUUID().toString();
        final String nonce = context.getNonce() != null ? context.getNonce() : UUID.randomUUID().toString();

        context.setStateAndNonce(state, nonce);
        contextAdapter.setContext(context);

        final ConfidentialClientApplication client = getConfidentialClientInstance();
        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(redirectUri, Collections.singleton(scopes)).responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT).state(state).nonce(nonce).build();

        final String authorizeUrl = client.getAuthorizationRequestUrl(parameters).toString();
        log.debug("authorizeUrl = {}", authorizeUrl);
        return authorizeUrl;
    }

    public void processAADCallback(IdentityContextAdapter contextAdapter) throws AuthException {
        log.info("processing redirect request...");
        final IdentityContextData context = contextAdapter.getContext();

        try {
            // FIRST, WE MUST VALIDATE THE STATE
            // ***** it is essential for CSRF protection ******
            // if no match, this throws an exception and we stop processing right here:
            validateState(contextAdapter);

            // if the state matches, continue, try to interpret any error codes.
            // e.g. redirect to pw reset. this will throw an error & cancel code x-change
            processErrorCodes(contextAdapter);

            // if no errors in request, continue to try to process auth code x-change:
            final String authCode = contextAdapter.getParameter("code");
            log.info("request code param is {}", authCode);
            if (authCode == null) // if no auth code, error out:
                throw new AuthException("Auth code is not in request!");

            // if auth code exists, proceed to exchange for token:
            log.info("Received AuthCode! Processing Auth code exchange...");

            // build the auth code params:
            final AuthorizationCodeParameters authParams = AuthorizationCodeParameters
                    .builder(authCode, new URI(redirectUri)).scopes(Collections.singleton(scopes))
                    .build();

            // Get a client instance and leverage it to acquire the token:
            final ConfidentialClientApplication client = getConfidentialClientInstance();
            final IAuthenticationResult result = client.acquireToken(authParams).get();

            // parse IdToken claims from the IAuthenticationResult:
            // (the next step - validateNonce - requires parsed claims)
            context.setIdTokenClaims(result.idToken());

            // if nonce is invalid, stop immediately! this could be a token replay!
            // if validation fails, throws exception and cancels auth:
            validateNonce(context);

            // set user to authenticated:
            context.setAuthResult(result, client.tokenCache().serialize());

            // handle groups overage if it has occurred.
            // optional: see groups sample.
            // you will need aad.scopes=GroupMember.Read.All in your config file.
            // uncomment the following method call if this is relevant to you:
            // handleGroupsOverage(contextAdapter);

        } catch (final Exception ex) {
            contextAdapter.setContext(null); // clear the session data since there was a problem
            String message = String.format("Unable to exchange auth code for token:%n %s", ex.getMessage());
            log.error(message);
            log.debug(Arrays.toString(ex.getStackTrace()));
            throw new AuthException(message);
        }
    }

    /**
     * If the user belongs to too many groups, and the ID token can't fit them all,
     * we must consult Microsoft Graph to get group memberships. Place the resulting
     * groups in IdentityContextData
     */
    private void handleGroupsOverage(IdentityContextAdapter contextAdapter) {
        IdentityContextData context = contextAdapter.getContext();
        if (context.getGroupsOverage()) {
            context.setGroups(GraphHelper.getGroups(GraphHelper.getGraphClient(contextAdapter)));
        }
    }

    private void validateState(IdentityContextAdapter contextAdapter) throws AuthException {
        log.info("validating state...");

        final String requestState = contextAdapter.getParameter("state");
        final IdentityContextData context = contextAdapter.getContext();
        final String sessionState = context.getState();
        final Date now = new Date();

        log.info("session state is: {} \n request state param is: {}",
                new String[] { sessionState, requestState });

        // if state is null or doesn't match or TTL expired, throw exception
        if (sessionState == null || requestState == null || !sessionState.equals(requestState)) {
            throw new AuthException("ValidateState() indicates state param mismatch, null, empty or expired.");
        } else if (context.getStateDate().before(new Date(now.getTime() - (ttl * 1000)))) {
            throw new AuthTtlException("Request has grown stale");
        }

        log.info("confirmed that state is valid and matches!");
        context.setState(null); // don't allow re-use of state
    }

    private void processErrorCodes(IdentityContextAdapter contextAdapter) throws AuthException {
        final String error = contextAdapter.getParameter("error");
        log.info("error is {}", error);
        final String errorDescription = contextAdapter.getParameter("error_description");
        log.info("error description is {}", errorDescription);
        if (error != null || errorDescription != null) {
            throw new AuthException(String.format("Received an error from AAD. Error: %s %nErrorDescription: %s", error,
                    errorDescription));
        }
    }

    private void validateNonce(IdentityContextData context) throws AuthException {
        log.info("validating nonce...");

        final String nonceClaim = (String) context.getIdTokenClaims().get("nonce");
        final String sessionNonce = context.getNonce();

        log.info("session nonce is: {} \n nonce claim in token is: {}",
                new String[] { sessionNonce, nonceClaim });
        if (sessionNonce == null || !sessionNonce.equals(nonceClaim)) {
            throw new AuthException("ValidateNonce() indicates that nonce validation failed.");
        }
        log.info("confirmed that nonce is valid and matches!");
        context.setNonce(null); // don't allow re-use of nonce
    }
}
