package au.edu.qcif.xnat.auth.openid.pkce;

import org.junit.Test;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.util.MultiValueMap;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit tests for {@link PkceAuthorizationCodeAccessTokenProvider}.
 *
 * <p>These exercise the PKCE-specific logic in isolation, with no live OAuth2 / OIDC provider:
 * the authorization-redirect path and the token-request parameter building are both reachable
 * without performing the HTTP token exchange. Lives in the same package as the provider so it can
 * read the package-private {@code PreservedState} the provider stashes on the request.</p>
 */
public class PkceAuthorizationCodeAccessTokenProviderTest {

    private static final String CLIENT_ID    = "xnat-client";
    private static final String AUTHORIZE_URI = "https://idp.example.org/authorize";
    private static final String TOKEN_URI     = "https://idp.example.org/token";
    private static final String REDIRECT_URI  = "https://xnat.example.org/openid-login";

    private static PkceAuthorizationCodeResourceDetails resource(final boolean pkceEnabled) {
        final PkceAuthorizationCodeResourceDetails resource = new PkceAuthorizationCodeResourceDetails();
        resource.setClientId(CLIENT_ID);
        resource.setUserAuthorizationUri(AUTHORIZE_URI);
        resource.setAccessTokenUri(TOKEN_URI);
        resource.setPreEstablishedRedirectUri(REDIRECT_URI);
        resource.setScope(Arrays.asList("openid", "email"));
        resource.setPkceEnabled(pkceEnabled);
        return resource;
    }

    private static PkceAuthorizationCodeAccessTokenProvider provider() {
        return new PkceAuthorizationCodeAccessTokenProvider(32);
    }

    /**
     * Drives {@code obtainAccessToken} with no code and no state, which makes the provider build and
     * throw the authorization redirect. Returns that exception; the passed-in request is mutated with
     * the generated state key and preserved state.
     */
    private static UserRedirectRequiredException triggerAuthorizationRedirect(
            final PkceAuthorizationCodeAccessTokenProvider provider,
            final PkceAuthorizationCodeResourceDetails resource,
            final AccessTokenRequest request) {
        try {
            provider.obtainAccessToken(resource, request);
            fail("Expected a UserRedirectRequiredException when no authorization code is present");
            return null; // unreachable
        } catch (UserRedirectRequiredException expected) {
            return expected;
        }
    }

    @SuppressWarnings("unchecked")
    private static MultiValueMap<String, String> invokeGetParametersForTokenRequest(
            final PkceAuthorizationCodeAccessTokenProvider provider,
            final PkceAuthorizationCodeResourceDetails resource,
            final AccessTokenRequest request) throws Exception {
        final Method method = PkceAuthorizationCodeAccessTokenProvider.class.getDeclaredMethod(
                "getParametersForTokenRequest", AuthorizationCodeResourceDetails.class, AccessTokenRequest.class);
        method.setAccessible(true);
        return (MultiValueMap<String, String>) method.invoke(provider, resource, request);
    }

    @Test
    public void redirectIncludesPkceChallengeAndStandardParameters() {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();

        final UserRedirectRequiredException redirect = triggerAuthorizationRedirect(provider(), resource(true), request);

        assertEquals(AUTHORIZE_URI, redirect.getRedirectUri());
        final Map<String, String> params = redirect.getRequestParams();
        assertEquals("code", params.get("response_type"));
        assertEquals(CLIENT_ID, params.get("client_id"));
        assertEquals("openid email", params.get("scope"));
        assertEquals(REDIRECT_URI, params.get("redirect_uri"));
        assertEquals("S256", params.get("code_challenge_method"));
        assertNotNull("code_challenge must be present when PKCE is enabled", params.get("code_challenge"));

        // The state key is generated, returned on the exception, and stashed on the request for later CSRF checks.
        assertNotNull(redirect.getStateKey());
        assertEquals(redirect.getStateKey(), request.getStateKey());

        // The code verifier is preserved client-side so it can be replayed at the token endpoint.
        final Object preserved = request.getPreservedState();
        assertTrue(preserved instanceof PkceAuthorizationCodeAccessTokenProvider.PreservedState);
        assertNotNull(((PkceAuthorizationCodeAccessTokenProvider.PreservedState) preserved).getCodeVerifier());
    }

    /**
     * The security-critical PKCE invariant: code_challenge == BASE64URL(SHA-256(code_verifier)).
     */
    @Test
    public void codeChallengeIsSha256OfCodeVerifier() throws Exception {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();

        final UserRedirectRequiredException redirect = triggerAuthorizationRedirect(provider(), resource(true), request);

        final String challenge = redirect.getRequestParams().get("code_challenge");
        final String verifier  = ((PkceAuthorizationCodeAccessTokenProvider.PreservedState) request.getPreservedState())
                .getCodeVerifier();

        final byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        final String expectedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        assertEquals(expectedChallenge, challenge);
    }

    @Test
    public void redirectOmitsPkceParametersWhenPkceDisabled() {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();

        final UserRedirectRequiredException redirect = triggerAuthorizationRedirect(provider(), resource(false), request);

        final Map<String, String> params = redirect.getRequestParams();
        assertNull("code_challenge must not be sent when PKCE is disabled", params.get("code_challenge"));
        assertNull("code_challenge_method must not be sent when PKCE is disabled", params.get("code_challenge_method"));
        assertNull(((PkceAuthorizationCodeAccessTokenProvider.PreservedState) request.getPreservedState()).getCodeVerifier());
    }

    @Test
    public void stateKeyHonoursConfiguredLength() {
        final PkceAuthorizationCodeAccessTokenProvider provider = new PkceAuthorizationCodeAccessTokenProvider(40);
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();

        final UserRedirectRequiredException redirect = triggerAuthorizationRedirect(provider, resource(true), request);

        assertEquals(40, redirect.getStateKey().length());
    }

    @Test
    public void tokenRequestReplaysCodeVerifierWhenPkceEnabled() throws Exception {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("auth-code-123");
        request.setPreservedState(new PkceAuthorizationCodeAccessTokenProvider.PreservedState(REDIRECT_URI, "the-code-verifier"));

        final MultiValueMap<String, String> form = invokeGetParametersForTokenRequest(provider(), resource(true), request);

        assertEquals("authorization_code", form.getFirst("grant_type"));
        assertEquals("auth-code-123", form.getFirst("code"));
        assertEquals("the-code-verifier", form.getFirst("code_verifier"));
        assertEquals(REDIRECT_URI, form.getFirst("redirect_uri"));
    }

    @Test
    public void tokenRequestOmitsCodeVerifierWhenPkceDisabled() throws Exception {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("auth-code-123");
        request.setPreservedState(new PkceAuthorizationCodeAccessTokenProvider.PreservedState(REDIRECT_URI, "the-code-verifier"));

        final MultiValueMap<String, String> form = invokeGetParametersForTokenRequest(provider(), resource(false), request);

        assertNull("code_verifier must not be sent when PKCE is disabled", form.getFirst("code_verifier"));
        assertEquals("authorization_code", form.getFirst("grant_type"));
        assertEquals("auth-code-123", form.getFirst("code"));
    }

    /**
     * State is mandatory by default, so a token request that arrives with an authorization code but no
     * preserved state is treated as a possible CSRF attack and rejected before any HTTP call is made.
     */
    @Test
    public void tokenRequestRejectsMissingStateAsPossibleCsrf() {
        final DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("auth-code-123");
        // No preserved state set.

        try {
            provider().obtainAccessToken(resource(true), request);
            fail("Expected an InvalidRequestException for missing state (possible CSRF)");
        } catch (InvalidRequestException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("csrf"));
        }
    }
}
