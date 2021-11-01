/**
 * JavaScript functions for providing OpenID Connect with NGINX Plus
 * 
 * Copyright (C) 2021 Nginx, Inc.
 */

// Constants for common error message. These will be cleaned up.
var ERR_CFG_VARS     = 'OIDC missing configuration variables: ';
var ERR_AC_TOKEN     = 'OIDC Access Token validation error: ';
var ERR_ID_TOKEN     = 'OIDC ID Token validation error: ';
var ERR_IDP_AUTH     = 'OIDC unexpected response from IdP when sending AuthZ code (HTTP ';
var ERR_TOKEN_RES    = 'OIDC AuthZ code sent but token response is not JSON. ';
var MSG_OK_REFRESH_TOKEN      = 'OIDC refresh success, updating id_token for ';
var MSG_REPLACE_REFRESH_TOKEN = 'OIDC replacing previous refresh token (';

// Flag to check if there is still valid session cookie. It is used by auth()
// and validateIdToken().
var newSession = false; 

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *   1. Export Functions: called by `oidc_server.conf` or any location block.  *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
export default {
    auth,
    codeExchange,
    validateIdToken,
    validateAccessToken,
    logout,
    redirectPostLogin,
    redirectPostLogout,
    passProxyServer,
    passProxyWithIdToken,
    passProxyWithAccessToken,
    passProxyWithIdAccessToken,
    passProxyWithoutToken,
    testExtractToken
};

// Start OIDC with either intializing new session or refershing token:
//
// 1. Start IdP authorization:
//  - Check all necessary configuration variables (referenced only by NJS).
//  - Redirect client to the IdP login page w/ the cookies we need for state.
//
// 2. Refresh ID / access token:
//  - Pass the refresh token to the /_refresh location so that it can be
//    proxied to the IdP in exchange for a new id_token and access_token.
//
function auth(r) {
    if (!r.variables.refresh_token || r.variables.refresh_token == '-') {
        startIdPAuthZ(r);
        return;
    }
    refershToken(r);
}

// Request OIDC token, and handle IDP response (error or successful token).
// This function is called by the IdP after successful authentication:
//
// 1. Request OIDC token:
//  - http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
//  - Pass the AuthZ code to the /_token location so that it can be proxied to
//    the IdP in exchange for a JWT.
//
// 2. Handle IDP response:
//  1) Error Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
//
//  2) Successful Token Response:
//   - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
//
function codeExchange(r) {
    if (!isValidAuthZCode(r)) {
        return
    }
    setTokenParams(r)
    r.subrequest('/_token', getTokenArgs(r),
        function(res) {
            var isErr = handleTokenErrorResponse(r, res)
            if (isErr) {
                clearTokenParams(r)
                return
            }
            handleSuccessfulTokenResponse(r, res)
        }
    );
}

// Call backend proxy that contains headers (ID token, access token, both, or none)
// based on the configuration of return_token_to_backend.
// The 'return_token_to_backend' can be also configured by APIM.
//
function passProxyServer(r) {
    switch(r.variables.return_token_to_backend) {
        case 'id_token':
            passProxyWithIdToken(r);
            break;
        case 'both':
            passProxyWithIdAccessToken(r);
            break;
        case 'access_token':
            passProxyWithAccessToken(r);
            break;
        default: 
            passProxyWithoutToken(r);
    }
}

// Call backend proxy that contains ID token in header.
// - Validate ID token
// - Set ID token to the key of x-id-token in the proxy header.
// - Pass backend proxy server with the ID token in the header.
function passProxyWithIdToken(r) {
    validateTokenPassProxy(r, '/_proxy_with_id_token')
}

// Call backend proxy that contains access token in header.
// - Validate access token.
// - Set Bearer access token in the proxy header.
// - Pass backend proxy server with the access token in the header.
function passProxyWithAccessToken(r) {
    validateTokenPassProxy(r, '/_proxy_with_access_token')
}

// Call backend proxy that contains ID/access token in header.
// - Validate access token.
// - Set Bearer access token in the proxy header.
// - Set ID token to the key of x-id-token in the proxy header.
// - Pass backend proxy server with the access token in the header.
function passProxyWithIdAccessToken(r) {
    validateTokenPassProxy(r, '/_proxy_with_id_access_token')
}

// Call backend proxy without token in header.
function passProxyWithoutToken(r) {
    validateTokenPassProxy(r, '/_proxy_without_token')
}

// Validate ID token which is received from IdP (fresh or refresh token):
//
// - https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
// - This function is called by the location of `_id_token_validation` which is
//   called by either OIDC code exchange or refersh token request.
// - The clients MUST validate the ID Token in the Token Response from the IdP.
//
function validateIdToken(r) {
    var missingClaims = []
    if (r.variables.jwt_audience.length == 0) missingClaims.push('aud');
    if (!isValidRequiredClaims(r, ERR_ID_TOKEN, missingClaims)) {
        r.return(403);
        return;
    }
    if (!isValidIatClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidAudClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    if (!isValidNonceClaim(r, ERR_ID_TOKEN)) {
        r.return(403);
        return;
    }
    r.return(204);
}

// Validate access token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation
// - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
// - This function is called by the location of `_access_token_validation` which
//   is called by either OIDC code exchange or refersh token request.
// - The 'aud' claim isn't contained in general ID token from Amazon Cognito,
//   although we can add it. Hence, the claim isn't part of this validation.
//
function validateAccessToken(r) {
    var missingClaims = []
    if (!isValidRequiredClaims(r, ERR_AC_TOKEN, missingClaims)) {
        r.return(403);
        return false;
    }
    if (!isValidIatClaim(r, ERR_AC_TOKEN)) {
        r.return(403);
        return false;
    }
    r.return(204);
    return true;
}

// RP-Initiated or Custom Logout w/ IDP
// 
// - An RP requests that the IDP log out the end-user by redirecting the
//   end-user's User Agent to the IDP's Logout endpoint.
// - TODO: Handle custom logout parameters if IDP doesn't support standard spec
//         of 'OpenID Connect RP-Initiated Logout 1.0'.
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
function logout(r) {
    r.log('OIDC logout for ' + r.variables.cookie_auth_token);
    var idToken = r.variables.id_token;
    r.variables.request_id    = '-';
    r.variables.id_token      = '-';
    r.variables.access_token  = '-';
    r.variables.refresh_token = '-';
    var logout_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_logout_endpoint,
        r.variables.oidc_custom_logout_path_params_enable,
        r.variables.oidc_custom_logout_path_params
    );
    var queryParams = '';

    // OIDC RP-initiated logout.
    if (r.variables.oidc_custom_logout_query_params_enable == 0) {
        queryParams = getRPInitiatedLogoutArgs(r, idToken);

    // Call the IDP logout endpoint with custom query parameters
    // if the IDP doesn't support RP-initiated logout.
    } else {
        queryParams = generateQueryParams(r.variables.oidc_custom_logout_query_params);
    }
    r.return(302, logout_endpoint + queryParams);
}

// Generate custom endpoint using path parameters if the option is enable.
// Otherwise, return the original endpoint.
//
// [Example 1]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/logout"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/logout"
//
// [Example 2]
// - Input : "https://{my-app}.okta.com/oauth2/{version}/authorize"
//   + {my-app}  -> 'dev-9590480'
//   + {version} -> 'v1'
// - Result: "https://dev-9590480.okta.okta.com/oauth2/v1/authorize"
//
function generateCustomEndpoint(r, uri, isEnableCustomPath, paths) {
    if (isEnableCustomPath == 0) {
        return uri;
    }
    var res   = '';
    var key   = '';
    var isKey = false;
    var items = JSON.parse(paths);
    for (var i = 0; i < uri.length; i++) {
        switch (uri[i]) {
            case '{': 
                isKey = true; 
                break;
            case '}': 
                res  += items[key]
                key   = '';
                isKey = false; 
                break;
            default : 
                if (!isKey) {
                    res += uri[i];
                } else {
                    key += uri[i];
                }
        }
    }
    r.log('generated an endpoint using path params: ' + res)
    return res;
}

// Redirect URI after logging in the IDP.
function redirectPostLogin(r) {
    r.return(302, r.variables.redirect_base + getIDTokenArgsAfterLogin(r));
}

// Redirect URI after logged-out from the IDP.
function redirectPostLogout(r) {
    r.return(302, r.variables.post_logout_return_uri);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                   2. Common Functions for OIDC Workflows                    *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Start Identity Provider (IdP) authorization:
//
// - Check all necessary configuration variables (referenced only by NJS).
// - Redirect the client to the IdP login page w/ the cookies we need for state.
//
function startIdPAuthZ(r) {
    r.log('### user-agent: ' + r.variables.http_user_agent)
    generateSession(r)
    newSession = true;

    var configs = ['authz_endpoint', 'scopes', 'hmac_key', 'cookie_flags'];
    var missingConfig = [];
    var authz_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_authz_endpoint,
        r.variables.oidc_custom_authz_path_params_enable,
        r.variables.oidc_custom_authz_path_params
    );

    for (var i in configs) {
        var oidcCfg = r.variables['oidc_' + configs[i]]
        if (!oidcCfg || oidcCfg == '') {
            missingConfig.push(configs[i]);
        }
    }
    if (missingConfig.length) {
        r.error(ERR_CFG_VARS + '$oidc_' + missingConfig.join(' $oidc_'));
        r.return(500, r.variables.internal_error_message);
        return;
    }
    r.return(302, authz_endpoint + getAuthZArgs(r));
}

// Handle error response regarding the referesh token received from IDP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
// - If the Refresh Request is invalid or unauthorized, the AuthZ Server returns
//   the Token Error Response as defined in OAuth 2.0 [RFC6749].
//
function handleRefershErrorResponse(r, res) {
    var msg = 'OIDC refresh failure';
    switch(res.status) {
        case 504:
            msg += ', timeout waiting for IdP';
            break;
        case 400:
            try {
                var errset = JSON.parse(res.responseBody);
                msg += ': ' + errset.error + ' ' + errset.error_description;
            } catch (e) {
                msg += ': ' + res.responseBody;
            }
            break;
        default:
            msg += ' '  + res.status;
    }
    r.error(msg);
    clearRefreshTokenAndReturnErr(r);
}

// Clear refersh token, and respond token error.
function clearRefreshTokenAndReturnErr(r) {
    r.variables.refresh_token = '-';
    r.return(302, r.variables.request_uri);
}

// Handle successful response regarding the referesh token:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
// - Upon successful validation of Refresh Token, the response body is the Token
//   Response of Section 3.1.3.3 except that it might not contain an id_token.
// - Successful Token Response except that it might not contain an id_token.
//
function handleSuccessfulRefreshResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
            clearRefreshTokenAndReturnErr(r);
            return;
        }

        // Update opaque ID token and access token to key/value store.
        r.variables.id_token     = tokenset.id_token;
        r.variables.access_token = tokenset.access_token;

        // Update new refresh token to key/value store if we got a new one.
        r.log(MSG_OK_REFRESH_TOKEN + r.variables.cookie_auth_token);
        if (r.variables.refresh_token != tokenset.refresh_token) {
            r.log(MSG_REPLACE_REFRESH_TOKEN + r.variables.refresh_token + 
                    ') with new value: ' + tokenset.refresh_token);
            r.variables.refresh_token = tokenset.refresh_token;
        }

        // Remove the evidence of original failed `auth_jwt`, and continue to
        // process the original request.
        delete r.headersOut['WWW-Authenticate'];
        r.internalRedirect(r.variables.request_uri);
    } catch (e) {
        clearRefreshTokenAndReturnErr(r);
    }
}

// Pass the refresh token to the /_refresh location so that it can be proxied to
// the IdP in exchange for a new id_token and access_token:
//
// 1. Request refresh token:
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
//  - To refresh an Access Token, the Client MUST authenticate to the Token
//    Endpoint using the authentication method registered for its client_id.
//
// 2. Handle IDP response(error or successful refresh token):
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse
//  - https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
//
function refershToken(r) {
    setTokenParams(r)
    r.subrequest('/_refresh', 'token=' + r.variables.refresh_token, respHandler);
    function respHandler(res) {
        if (res.status != 200) {
            handleRefershErrorResponse(r, res);
            clearTokenParams(r)
            return;
        }
        handleSuccessfulRefreshResponse(r, res);
    }
}

// Set query/path parameters to the IDP token endpoint if customization option 
// for query or path param is enable.
function setTokenParams(r) {
    clearTokenParams(r)
    if (r.variables.oidc_custom_token_query_params_enable == 1) {
        r.variables.token_query_params = generateQueryParams(
            r.variables.oidc_custom_token_query_params
        );
    }
    r.variables.oidc_custom_token_endpoint = generateCustomEndpoint(r,
        r.variables.oidc_token_endpoint,
        r.variables.oidc_custom_token_path_params_enable,
        r.variables.oidc_custom_token_path_params
    );
}

// Clear query parameters of the temporary stroage for the NGINX if OIDC's token
// endpoint returns error.
function clearTokenParams(r) {
    r.variables.token_query_params = '';
}

// Handle error response regarding the token received from IDP token endpoint:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
// - If the Token Request is invalid or unauthorized, the Authorization Server
//   constructs the error response.
// - The HTTP response body uses the application/json media type with HTTP 
//   response code of 400.
//
function handleTokenErrorResponse(r, res) {
    var isErr = true
    if (res.status == 504) {
        r.error('OIDC timeout connecting to IdP when sending AuthZ code');
        r.return(504);
        return isErr;
    }
    if (res.status != 200) {
        try {
            var errset = JSON.parse(res.responseBody);
            if (errset.error) {
                r.error('OIDC error from IdP when sending AuthZ code: ' +
                    errset.error + ', ' + errset.error_description);
            } else {
                r.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
            }
        } catch (e) {
            r.error(ERR_IDP_AUTH + res.status + '). ' + res.responseBody);
        }
        r.return(502);
        return isErr;
    }
    return !isErr;
}

// Handle tokens after getting successful token response from the IdP:
//
// - https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
// - After receiving and validating a valid and authorized Token Request from
//   the Client, the Authorization Server returns a successful response that 
//   includes an ID Token and an Access Token.
//
function handleSuccessfulTokenResponse(r, res) {
    try {
        var tokenset = JSON.parse(res.responseBody);
        var isErr = isValidTokenSet(r, tokenset);
        if (isErr) {
             r.return(500);
             return;
        }

        // Add opaque ID token and access token to key/value store
        r.variables.new_id_token     = tokenset.id_token;
        r.variables.new_access_token = tokenset.access_token;

        // Add new refresh token to key/value store
        if (tokenset.refresh_token) {
            r.variables.new_refresh = tokenset.refresh_token;
            r.log('OIDC refresh token stored');
        } else {
            r.warn('OIDC no refresh token');
        }
        // Set cookie with request ID that is the key of each ID/access token,
        // and continue to process the original request.
        r.log('OIDC success, creating session '    + r.variables.request_id);
        r.headersOut['Set-Cookie'] = 'auth_token=' + r.variables.request_id + 
                                     '; ' + r.variables.oidc_cookie_flags;
        r.return(302, r.variables.redirect_base + r.variables.cookie_auth_redir);
    } catch (e) {
        r.error(ERR_TOKEN_RES + res.responseBody);
        r.return(502);
    }
}

// Check if token is valid using `auth_jwt` directives and Node.JS functions:
//
// - ID     token validation: uri('/_id_token_validation'    )
// - Access token validation: uri('/_access_token_validation')
//
function isValidToken(r, uri, token) {
    if (!token) {
        return false
    }
    var isValid = true
    r.subrequest(uri, 'token=' + token, function(res) {
        if (res.status != 204) {
            isValid = false
        }
    });
    return isValid;
}

// Generate cookie and query parameters using the OIDC config in the nginx.conf:
//
// - Both are used when calling the API endpoint of IdP authorization for the
//   first time when starting Open ID Connect handshaking.
// - Choose a nonce for this flow for the client, and hash it for the IdP.
//
function getAuthZArgs(r) {
    var noncePlain = r.variables.request_id;
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(noncePlain);
    var nonceHash   = h.digest('base64url');
    var redirectURI = r.variables.redirect_base + r.variables.redir_location;
    var authZArgs   = '?response_type=code&scope=' + r.variables.oidc_scopes +
                      '&client_id='                + r.variables.oidc_client + 
                      '&redirect_uri='             + redirectURI; + 
                      '&nonce='                    + nonceHash;
    var cookieFlags = r.variables.oidc_cookie_flags;
    r.headersOut['Set-Cookie'] = [
        'auth_redir=' + r.variables.request_uri + '; ' + cookieFlags,
        'auth_nonce=' + noncePlain + '; ' + cookieFlags
    ];
    r.variables.nonce_hash = nonceHash;

    if (r.variables.oidc_pkce_enable == 1) {
        var pkce_code_verifier  = c.createHmac('sha256', r.variables.oidc_hmac_key).
                                    update(randomStr()).digest('hex');
        r.variables.pkce_id     = c.createHash('sha256').
                                    update(randomStr()).digest('base64url');
        var pkce_code_challenge = c.createHash('sha256').
                                    update(pkce_code_verifier).digest('base64url');
        r.variables.pkce_code_verifier = pkce_code_verifier;

        authZArgs += '&code_challenge_method=S256&code_challenge=' + 
                     pkce_code_challenge + '&state=' + r.variables.pkce_id;
    } else {
        authZArgs += '&state=0';
    }

    if (r.variables.oidc_custom_authz_query_params_enable == 1) {
        return generateQueryParams(r.variables.oidc_custom_authz_query_params);
    }
    return authZArgs;
}

// Generate custom query parameters from JSON object
function generateQueryParams(obj) {
    var items = JSON.parse(obj);
    var args = '?'
    for (var key in items) {
        args += key + '=' + items[key] + '&'
    }
    return args.slice(0, -1)
}

// Generate and return random string.
function randomStr() {
    return String(Math.random())
}

// Get query parameter of ID token after sucessful login.
// - For the variable of `returnTokenToClientOnLogin` of the APIM, this config
//   is only effective for /login endpoint. By default, our implementation MUST
//   not return any token back to the client app. 
// - If its configured it can send id_token in the request uri as 
//   `?id_token=sdfsdfdsfs` after successful login. 
//
function getIDTokenArgsAfterLogin(r) {
    if (r.variables.return_token_to_client_on_login == 'id_token') {
        return '?id_token=' + r.variables.id_token;
    }
    return '';
}

// Get query params for RP-initiated logout:
//
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
// - https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout
//
function getRPInitiatedLogoutArgs(r, idToken) {
    return '?post_logout_redirect_uri=' + r.variables.redirect_base
                                        + r.variables.oidc_logout_redirect +
           '&id_token_hint='            + idToken;
}

// Set PKCE ID and generate query parameters for OIDC token endpoint:
//
// - If PKCE is enabled, then we have to use the code_verifier.
// - Otherwise, we use client secret.
//
function getTokenArgs(r) {
    if (r.variables.oidc_pkce_enable == 1) {
        r.variables.pkce_id = r.variables.arg_state;
        return 'code='           + r.variables.arg_code + 
               '&code_verifier=' + r.variables.pkce_code_verifier;
    } else {
        return 'code='           + r.variables.arg_code + 
               '&client_secret=' + r.variables.oidc_client_secret;
    }
}

// Validate authorization code if it is correctly received from the IdP.
function isValidAuthZCode(r) {
    if (r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error('OIDC error receiving AuthZ code from IdP: ' +
                r.variables.arg_error_description);
        } else {
            r.error('OIDC expected AuthZ code from IdP but received: ' + r.uri);
        }
        r.return(502);
        return false;
    }
    return true;
}

// Validate 'iat' claim to see if it is valid:
//
// - Check if `iat` is a positive integer.
// - TODO if needed:
//   + It can be used to reject tokens that were issued too far away from
//     the current time, limiting the amount of time that nonces need to be
//     stored to prevent attacks. The acceptable range is Client specific.
//
function isValidIatClaim(r, msgPrefix) {
    var iat = Math.floor(Number(r.variables.jwt_claim_iat));
    if (String(iat) != r.variables.jwt_claim_iat || iat < 1) {
        r.error(msgPrefix + 'iat claim is not a valid number');
        return false;
    }
    return true;
}

// Validate 'aud (audience)' claim to see if it is valid:
//
// - The client MUST validate that `aud` claim contains its client_id value
//   registered at the Issuer identified by `iss` claim as an audience.
// - The ID Token MUST be rejected if the ID Token does not list the client
//   as a valid audience, or if it contains additional audiences not trusted
//   by the client.
//
function isValidAudClaim(r, msgPrefix) {
    var aud = r.variables.jwt_audience.split(',');
    if (!aud.includes(r.variables.oidc_client)) {
        r.error(msgPrefix + 'aud claim (' + r.variables.jwt_audience +
            ') does not include configured $oidc_client (' + 
            r.variables.oidc_client + ')');
            return false;
    }
    return true;
}

// Validate `nonce` claim to mitigate replay attacks:
//
// - nonce: a string value used to associate a client session & an ID token. 
//   The value is used to mitigate replay attacks and is present only if 
//   passed during the authorization request.
// - If we receive a nonce in the ID Token then we will use the auth_nonce 
//   cookies to check that JWT can be validated as being directly related to
//   the original request by this client. 
function isValidNonceClaim(r, msgPrefix) {
    if (newSession) {
        var clientNonceHash = '';
        if (r.variables.cookie_auth_nonce) {
            var c = require('crypto');
            var h = c.createHmac('sha256', r.variables.oidc_hmac_key).
                        update(r.variables.cookie_auth_nonce);
            clientNonceHash = h.digest('base64url');
        }
        if (r.variables.jwt_claim_nonce != clientNonceHash) {
            r.error(msgPrefix + 'nonce from token (' + 
                r.variables.jwt_claim_nonce + ') does not match client (' + 
                clientNonceHash + ')');
            return false;
        }
    }
    return true;
}

// Validate if received token from the IdP contains mandatory claims:
//
// - For ID     token: 'iat', 'iss', 'sub', 'aud'
// - For Access token: 'iat', 'iss', 'sub'
// - Given the RFC7519, the above claims are OPTIONAL. But, we validate them
//   as required claims for several purposes such as mitigating replay attacks.
//
function isValidRequiredClaims(r, msgPrefix, missingClaims) {
    var required_claims = ['iat', 'iss', 'sub'];
    try {
        for (var i in required_claims) {
            if (r.variables['jwt_claim_' + required_claims[i]].length == 0 ) {
                missingClaims.push(required_claims[i]);
            }
        }
        if (missingClaims.length) {
            r.error(msgPrefix + 'missing claim(s) ' + missingClaims.join(' '));
            return false;
        }
    } catch (e) {
        r.error("required claims or missing claims do not exist.")
        return false
    }
    return true
}

// Check if (fresh or refersh) token set (ID token, access token) is valid.
function isValidTokenSet(r, tokenset) {
    var isErr = true;
    if (tokenset.error) {
        r.error('OIDC ' + tokenset.error + ' ' + tokenset.error_description);
        return isErr;
    }
    if (!tokenset.id_token) {
        r.error('OIDC response did not include id_token');
        return isErr;
    }
    if (!tokenset.access_token) {
        r.error('OIDC response did not include access_token');
        return isErr;
    }
    if (!isValidToken(r, '/_id_token_validation', tokenset.id_token)) {
        // The validateIdToken() logs error so that r.error() isn't used.
        return isErr;
    }
    if (!isValidToken(r, '/_access_token_validation', tokenset.access_token)) {
        // The validateAccessToken() logs error so that r.error() isn't used.
        return isErr;
    }
    return !isErr;
}

// Validate ID/access token and pass backend proxy.
function validateTokenPassProxy(r, uri) {
    r.subrequest(uri, function(res) {
        if (res.status != 200) {
            r.error('validate token and pass backend proxy: ' + res.status);
            r.return(res.status)
            return
        }
        r.return(res.status, res.responseBody)
    });
}
function fromBase64String(str) {
    var alpha = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var value = [];
    var index = 0;
    var destIndex  = 0;
    var padding = false;
    while (true) {

        var first  = getNextChr(str, index, padding, alpha);
        var second = getNextChr(str, first .nextIndex, first .padding, alpha);
        var third  = getNextChr(str, second.nextIndex, second.padding, alpha);
        var fourth = getNextChr(str, third .nextIndex, third .padding, alpha);

        index = fourth.nextIndex;
        padding = fourth.padding;

        // ffffffss sssstttt ttffffff
        var base64_first  = first.code  == null ? 0 : first.code;
        var base64_second = second.code == null ? 0 : second.code;
        var base64_third  = third.code  == null ? 0 : third.code;
        var base64_fourth = fourth.code == null ? 0 : fourth.code;

        var a = (( base64_first << 2) & 0xFC ) | ((base64_second>>4) & 0x03);
        var b = (( base64_second<< 4) & 0xF0 ) | ((base64_third >>2) & 0x0F);
        var c = (( base64_third << 6) & 0xC0 ) | ((base64_fourth>>0) & 0x3F);

        value [destIndex++] = a;
        if (!third.padding) {
            value [destIndex++] = b;
        } else {
            break;
        }
        if (!fourth.padding) {
            value [destIndex++] = c;
        } else {
            break;
        }
        if (index >= str.length) {
            break;
        }
    }
    return value;
}

function getNextChr(str, index, equalSignReceived, alpha) {
    var chr = null;
    var code = 0;
    var padding = equalSignReceived;
    while (index < str.length) {
        chr = str.charAt(index);
        if (chr == " " || chr == "\r" || chr == "\n" || chr == "\t") {
            index++;
            continue;
        }
        if (chr == "=") {
            padding = true;
        } else {
            if (equalSignReceived) {
                throw new Error("Invalid Base64 Endcoding character \"" 
                    + chr + "\" with code " + str.charCodeAt(index) 
                    + " on position " + index 
                    + " received afer an equal sign (=) padding "
                    + "character has already been received. "
                    + "The equal sign padding character is the only "
                    + "possible padding character at the end.");
            }
            code = alpha.indexOf(chr);
            if (code == -1) {
                throw new Error("Invalid Base64 Encoding character \"" 
                    + chr + "\" with code " + str.charCodeAt(index) 
                    + " on position " + index + ".");
            }
        }
        break;
    }
    return { character: chr, code: code, padding: padding, nextIndex: ++index};
}

function strToArrayBuffer(str) {
    var buf = new ArrayBuffer(str.length * 2);
    var bufView = new Uint16Array(buf);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
  
function arrayBufferToString(buffer) {
    return String.fromCharCode.apply(null, new Uint16Array(buffer));
}

function decryptSession(r, cipherText, vector, key1) {
    var keyData = Buffer.from(r.variables.session_key, 'base64');
    // var vector    = crypto.getRandomValues(new Uint32Array(16));
    r.log('### vector: ' + vector)
    var resKey = crypto.subtle.importKey('raw', keyData, 'AES-GCM', false,
                                            ['encrypt', 'decrypt']);
    resKey.then(function(key){ // CryptoKey object
        var res = crypto.subtle.decrypt(
            {name: 'AES-GCM', iv: vector}, key, cipherText
        );
        res.then(function(buf){ 
            r.log('### decrypted session: ' + buf);
            r.log("### decrypted session str 1: " + arrayBufferToString(buf));
            r.log("### decrypted session str 2: " + arrayBufferToString(buf).toString());
            r.log("### decrypted session str 3: " + arrayBufferToString(buf).toString('hex'));
        }).catch (function (err) {
            r.log('### Error: ' + err.message);
        });
    });
}

// Generate session ID
function generateSession(r) {
    r.log("### start generating session ID");

    var dt = new Date(Date.now());
    var sessionObj = {
        "userAgent" : r.variables.http_user_agent,
        "clientID"  : r.variables.oidc_client,
        "requestID" : r.variables.request_id,
        "timestamp" : dt.getHours() + ":" + dt.getMinutes()
    };
    var strSession = JSON.stringify(sessionObj);
    if (strSession.length % 2 == 1) {
        strSession += ' ';
    }
    r.log("### JSON   session: " + sessionObj)
    r.log("### string session: " + strSession)
    r.log("### request ID: " + r.variables.request_id)

    var keyData = Buffer.from(r.variables.session_key, 'base64');
    var buffer  = strToArrayBuffer(strSession);
    var vector  = crypto.getRandomValues(new Uint32Array(16));
    var resKey  = crypto.subtle.importKey('raw', keyData, 'AES-GCM', false,
                                            ['encrypt', 'decrypt']);
    resKey.then(function(key){ // CryptoKey object
        var encrypted = crypto.subtle.encrypt(
            {name: 'AES-GCM', iv: vector, length: 256}, key, buffer
        )
        encrypted.then(function (cipherText) {
            r.log('### Cipher Text 1: ' + arrayBufferToString(cipherText).toString('hex'));
            decryptSession(r, cipherText, vector, key)
        }).then(function (plainText) {
            r.log('### Plain Text: ' + arrayBufferToString(plainText).toString());
        }).catch (function (err) {
            r.log('### Error: ' + err.message);
        });
    });
    //     var encrypted = crypto.subtle.encrypt(
    //         {name: 'AES-GCM', iv: vector}, key, buffer
    //     )
    //     encrypted.then(function(res){ // ArrayBuffer object
    //         var encryptSession = arrayBufferToString(res).toString('hex');
    //         r.log("### encrypted session ID str (hex): " + encryptSession)
    //         decryptSession(r, encryptSession, vector)
    //     })
    //     .catch(function(error) {
    //         r.log("### encrypted session exception: " + error)
    //     });
    // })
    // .catch(function(error) {
    //     r.log("### import key exception: " + error)
    // });

    // var encryptSessionId = encryptString(strSession, key, iv)
    // r.log("### encrypted session ID: " + encryptSessionId)
    // var decryptSessionId = decryptString(encryptSessionId, key, iv)
    // r.log("### decrypted session ID: " + decryptSessionId)

    return strSession;
}

// function encryptString(string, key, iv) {
//     var cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
//     cipher.update(string, 'utf-8', 'hex');
//     return cipher.final('hex');
// }

// function decryptString(c, string, key, iv) {
//     var decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
//     decipher.update(string, 'hex', 'utf-8');
//     return decipher.final('utf-8');
// }


// Extract ID/access token from the request header.
function extractToken(r, key, is_bearer, validation_uri, msg) {
    var token = '';
    try {
        var headers = r.headersIn[key].split(' ');
        if (is_bearer) {
            if (headers[0] === 'Bearer') {
                token = headers[1]
            } else {
                msg += `, "` + key + `": "N/A"`;
                return [true, msg]
            }
        } else {
            token = headers[0]
        }
        if (!isValidToken(r, validation_uri, token)) {
            msg += `, "` + key + `": "invalid"}\n`;
            r.return(401, msg);
            return [false, msg];
        } else {
            msg += `, "` + key + `": "` + token + `"`;
        }
    } catch (e) {
        msg += `, "` + key + ` in header": "N/A"`;
    }
    return [true, msg]
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                             *
 *                      3. Common Functions for Testing                        *
 *                                                                             *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Test for extracting bearer token from the header of API request.
function testExtractToken (r) {
    var msg = `{
        "message": "This is to show which token is part of proxy header(s) in a server app.",
        "uri":"` + r.variables.request_uri + `"`;
    var res = extractToken(r, 'Authorization', true, '/_access_token_validation', msg)
    if (!res[0]) {
        return 
    }
    msg = res[1]

    var res = extractToken(r, 'x-id-token', false, '/_id_token_validation', msg)
    if (!res[0]) {
        return 
    }
    msg = res[1]

    var body = msg + '}\n';
    r.return(200, body);
}


var browser_slash_v123_names = [
    'ANTGalio',
    'Camino',
    'Chrome',
    'Demeter',
    'Dillo',
    'Epiphany',
    'Fennec',
    'Flock',
    'Fluid',
    'Fresco',
    'Galeon',
    'GranParadiso',
    'IceWeasel',
    'Iceape',
    'Iceweasel',
    'Iris',
    'Iron',
    'Jasmine',
    'K-Meleon',
    'Kazehakase',
    'Konqueror',
    'Lobo',
    'Lunascape',
    'Lynx',
    'Maxthon',
    'Midori',
    'NetFront',
    'NetNewsWire',
    'Netscape',
    'OmniWeb',
    'Opera Mini',
    'SeaMonkey',
    'Shiira',
    'Sleipnir',
    'Sunrise',
    'Vienna',
    'Vodafone',
    'WebPilot',
    'iCab'
  ],
  browser_slash_v123_names_pattern = '(' + browser_slash_v123_names.join('|') + ')'
  
  var browser_slash_v12_names = [
    'Arora',
    'BOLT',
    'Bolt',
    'Camino',
    'Chrome',
    'Dillo',
    'Dolfin',
    'Epiphany',
    'Fennec',
    'Flock',
    'Galeon',
    'GranParadiso',
    'IBrowse',
    'IceWeasel',
    'Iceape',
    'Iceweasel',
    'Iron',
    'Jasmine',
    'K-Meleon',
    'Kazehakase',
    'Konqueror',
    'Lunascape',
    'Lynx',
    'Maxthon',
    'Midori',
    'NetFront',
    'NetNewsWire',
    'Netscape',
    'Opera Mini',
    'Opera',
    'Orca',
    'Phoenix',
    'SeaMonkey',
    'Shiira',
    'Sleipnir',
    'Space Bison',
    'Stainless',
    'Vienna',
    'Vodafone',
    'WebPilot',
    'iCab',
  ],
  browser_slash_v12_names_pattern = '(' + browser_slash_v12_names.join('|') + ')'
  
  var replace = function(type, replacement) {
    return function(components) {
      component_matches = replacement.match(/\$([a-z]+)/g)
      if (component_matches)
        component_matches.forEach(function(match) {
          var component = match.substring(1)
          components[type] = replacement.replace(match, components[component])
        })
      else
        components[type] = replacement
    }
  }
  
  //
  // Given a User-Agent HTTP header string, parse it to extract the browser "family", 
  // (eg, "Safari", "Firefox", "IE"), and the major, minor, and tertiary version numbers.
  //
  // Note: Some browsers have a quaternary number, but this code stops at tertiary version numbers.
  //
  function parse(useragent) {
  
    var p = function() {
      var args = Array.prototype.slice.call(arguments, 0),
          regexp = args.shift()
          callbacks = args,
          match = useragent.match(regexp)
  
      if (match) {
        var components = {
          family: match[1],
          v1: match[2],
          v2: match[3],
          v3: match[4]
        }
        callbacks.forEach(function(cb) {
          cb(components)
        })
  
        return components
      }
      else
        return false
    }
  
  
    return (
      // Special Cases ---------------------------------------------------------------------
  
      // must go before Opera
      p(/^(Opera)\/(\d+)\.(\d+) \(Nintendo Wii/, replace('family', 'Wii')) ||
      //  // must go before Browser/v1.v2 - eg: Minefield/3.1a1pre
      p(/(Namoroka|Shiretoko|Minefield)\/(\d+)\.(\d+)\.(\d+(?:pre)?)/, replace('family', 'Firefox ($family)')) ||
      p(/(Namoroka|Shiretoko|Minefield)\/(\d+)\.(\d+)([ab]\d+[a-z]*)?/, replace('family', 'Firefox ($family)')) ||
      p(/(MozillaDeveloperPreview)\/(\d+)\.(\d+)([ab]\d+[a-z]*)?/) ||
      p(/(SeaMonkey|Fennec|Camino)\/(\d+)\.(\d+)([ab]?\d+[a-z]*)/) ||
      // e.g.: Flock/2.0b2
      p(/(Flock)\/(\d+)\.(\d+)(b\d+?)/) ||
  
      // e.g.: Fennec/0.9pre
      p(/(Fennec)\/(\d+)\.(\d+)(pre)/) ||
      p(/(Navigator)\/(\d+)\.(\d+)\.(\d+)/,   replace('family', 'Netscape')) ||
      p(/(Navigator)\/(\d+)\.(\d+)([ab]\d+)/, replace('family', 'Netscape')) ||
      p(/(Netscape6)\/(\d+)\.(\d+)\.(\d+)/,   replace('family', 'Netscape')) ||
      p(/(MyIBrow)\/(\d+)\.(\d+)/,            replace('family', 'My Internet Browser')) ||
      p(/(Firefox).*Tablet browser (\d+)\.(\d+)\.(\d+)/, replace('family', 'MicroB')) ||
      // Opera will stop at 9.80 and hide the real version in the Version string.
      // see: http://dev.opera.com/articles/view/opera-ua-string-changes/
      p(/(Opera)\/.+Opera Mobi.+Version\/(\d+)\.(\d+)/, replace('family', 'Opera Mobile')) ||
      p(/(Opera)\/9.80.*Version\/(\d+)\.(\d+)(?:\.(\d+))?/) ||
  
      // Palm WebOS looks a lot like Safari.
      p(/(webOS)\/(\d+)\.(\d+)/, replace('family', 'Palm webOS')) ||
  
      p(/(Firefox)\/(\d+)\.(\d+)\.(\d+(?:pre)?) \(Swiftfox\)/,  replace('family', 'Swiftfox')) ||
      p(/(Firefox)\/(\d+)\.(\d+)([ab]\d+[a-z]*)? \(Swiftfox\)/, replace('family', 'Swiftfox')) ||
  
      // catches lower case konqueror
      p(/(konqueror)\/(\d+)\.(\d+)\.(\d+)/, replace('family', 'Konqueror')) ||
  
      // End Special Cases -----------------------------------------------------------------
  
  
    
      // Main Cases - this catches > 50% of all browsers------------------------------------
      // Browser/v1.v2.v3
      p(browser_slash_v123_names_pattern + '/(\\d+)\.(\\d+)\.(\\d+)') ||
      // Browser/v1.v2
      p(browser_slash_v12_names_pattern + '/(\\d+)\.(\\d+)') ||
      // Browser v1.v2.v3 (space instead of slash)
      p(/(iRider|Crazy Browser|SkipStone|iCab|Lunascape|Sleipnir|Maemo Browser) (\d+)\.(\d+)\.(\d+)/) ||
      // Browser v1.v2 (space instead of slash)
      p(/(iCab|Lunascape|Opera|Android) (\d+)\.(\d+)/) ||
      p(/(IEMobile) (\d+)\.(\d+)/, replace('family', 'IE Mobile')) ||
      // DO THIS AFTER THE EDGE CASES ABOVE!
      p(/(Firefox)\/(\d+)\.(\d+)\.(\d+)/) ||
      p(/(Firefox)\/(\d+)\.(\d+)(pre|[ab]\d+[a-z]*)?/) ||
      // End Main Cases --------------------------------------------------------------------
    
      // Special Cases ---------------------------------------------------------------------
      p(/(Obigo|OBIGO)[^\d]*(\d+)(?:.(\d+))?/, replace('family', 'Obigo')) ||
      p(/(MAXTHON|Maxthon) (\d+)\.(\d+)/, replace('family', 'Maxthon')) ||
      p(/(Maxthon|MyIE2|Uzbl|Shiira)/, replace('v1', '0')) ||
      p(/(PLAYSTATION) (\d+)/, replace('family', 'PlayStation')) ||
      p(/(PlayStation Portable)[^\d]+(\d+).(\d+)/) ||
      p(/(BrowseX) \((\d+)\.(\d+)\.(\d+)/) ||
      p(/(POLARIS)\/(\d+)\.(\d+)/, replace('family', 'Polaris')) ||
      p(/(BonEcho)\/(\d+)\.(\d+)\.(\d+)/, replace('family', 'Bon Echo')) ||
      p(/(iPhone) OS (\d+)_(\d+)(?:_(\d+))?/) ||
      p(/(iPad).+ OS (\d+)_(\d+)(?:_(\d+))?/) ||
      p(/(Avant)/, replace('v1', '1')) ||
      p(/(Nokia)[EN]?(\d+)/) ||
      p(/(Black[bB]erry).+Version\/(\d+)\.(\d+)\.(\d+)/, replace('family', 'Blackberry')) ||
      p(/(Black[bB]erry)\s?(\d+)/, replace('family', 'Blackberry')) ||
      p(/(OmniWeb)\/v(\d+)\.(\d+)/) ||
      p(/(Blazer)\/(\d+)\.(\d+)/, replace('family', 'Palm Blazer')) ||
      p(/(Pre)\/(\d+)\.(\d+)/, replace('family', 'Palm Pre')) ||
      p(/(Links) \((\d+)\.(\d+)/) ||
      p(/(QtWeb) Internet Browser\/(\d+)\.(\d+)/) ||
      p(/\(iPad;.+(Version)\/(\d+)\.(\d+)(?:\.(\d+))?.*Safari\//, replace('family', 'iPad')) ||
      p(/(Version)\/(\d+)\.(\d+)(?:\.(\d+))?.*Safari\//, replace('family', 'Safari')) ||
      p(/(OLPC)\/Update(\d+)\.(\d+)/) ||
      p(/(OLPC)\/Update()\.(\d+)/, replace('v1', '0')) ||
      p(/(SamsungSGHi560)/, replace('family', 'Samsung SGHi560')) ||
      p(/^(SonyEricssonK800i)/, replace('family', 'Sony Ericsson K800i')) ||
      p(/(Teleca Q7)/) ||
      p(/(MSIE) (\d+)\.(\d+)/, replace('family', 'IE')) ||
      // End Special Cases -----------------------------------------------------------------
      {family: 'Other'}
    
    )
  }
  
  //
  // Simply returns a nicely formatted user agent.
  //
  function prettyParse(useragent) {
    var components = parse(useragent),
        family = components.family,
        v1 = components.v1,
        v2 = components.v2,
        v3 = components.v3,
        prettyString = family
  
    if (v1) {
      prettyString += ' ' + v1
      if (v2) {
        prettyString += '.' + v2
        if (v3) {
          var match = v3.match(/^[0-9]/)
          prettyString += (match ? '.' : ' ') + v3
        }
      }
    }
    return prettyString
  }