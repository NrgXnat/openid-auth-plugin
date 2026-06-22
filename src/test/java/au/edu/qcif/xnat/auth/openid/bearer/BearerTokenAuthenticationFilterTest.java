package au.edu.qcif.xnat.auth.openid.bearer;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.OpenIdUserResolver;
import au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateFactory;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Status-mapping tests for {@link BearerTokenAuthenticationFilter}, driven through real signed tokens
 * (offline RSA keys) with the validator's keys supplied in-memory. Asserts the 401/403 contract, the
 * pass-through and already-authenticated short-circuits, that a valid token sets an
 * {@link OpenIdAuthToken}, and that no {@code HttpSession} is created (the bearer path is stateless).
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationFilterTest {

    private static final String PROVIDER = "keycloak";
    private static final String ISSUER = "https://idp.example/realms/xnat";
    private static final String USERNAME = "keycloak_alice"; // default pattern [providerId]_[sub], sub="alice"

    private static RSAKey signingKey;
    private static RSAKey strangerKey;
    private static JWKSource<SecurityContext> trustedSource;

    @Mock private OpenIdAuthPlugin plugin;
    @Mock private OpenIdUserResolver userResolver;

    private BearerTokenAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @BeforeClass
    public static void generateKeys() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        strangerKey = new RSAKeyGenerator(2048).keyID("k2").generate();
        trustedSource = new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));
    }

    @Before
    public void setUp() {
        // Provider config that makes BearerProviderResolver route ISSUER -> PROVIDER.
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        lenient().when(plugin.getProperty(PROVIDER, "bearer.enabled")).thenReturn("true");
        lenient().when(plugin.getProperty(PROVIDER, OpenIdAuthConstant.ISSUER)).thenReturn(ISSUER);
        lenient().when(plugin.getProperty(PROVIDER, OpenIdAuthConstant.JWKS_URI)).thenReturn("https://idp.example/jwks");

        final Map<String, BearerTokenValidator> validators =
                Collections.singletonMap(PROVIDER, new BearerTokenValidator(ISSUER, trustedSource));

        filter = new BearerTokenAuthenticationFilter(plugin, new BearerTokenExtractor(),
                new BearerProviderResolver(plugin), validators, new ClaimGateFactory(plugin), userResolver);

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    // ---- helpers -------------------------------------------------------------------------------

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000));
    }

    private static String sign(final RSAKey key, final JWTClaimsSet claims) throws Exception {
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private void bearer(final String token) {
        request.addHeader("Authorization", "Bearer " + token);
    }

    private UserI enabledUser() {
        final UserI user = mock(UserI.class);
        lenient().when(user.getUsername()).thenReturn(USERNAME);
        lenient().when(user.isEnabled()).thenReturn(true);
        lenient().when(user.isAccountNonLocked()).thenReturn(true);
        // getAuthorities() is left unstubbed (null) — Spring's AbstractAuthenticationToken maps that
        // to NO_AUTHORITIES, and stubbing it trips Mockito on UserI's generic signature.
        return user;
    }

    private void doFilter() throws Exception {
        filter.doFilter(request, response, chain);
    }

    private static Authentication currentAuth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    // ---- pass-through / short-circuit ----------------------------------------------------------

    @Test
    public void noBearerHeaderPassesThrough() throws Exception {
        doFilter();

        assertNotNull("chain should be invoked", chain.getRequest());
        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        assertNull(currentAuth());
        assertNull("no session should be created", request.getSession(false));
    }

    @Test
    public void alreadyAuthenticatedRequestSkipsBearerPipeline() throws Exception {
        final Authentication preAuth = mock(Authentication.class);
        when(preAuth.isAuthenticated()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(preAuth);
        bearer(sign(signingKey, validClaims().build()));

        doFilter();

        assertNotNull("chain should be invoked", chain.getRequest());
        assertSame("the upstream authentication must be left untouched", preAuth, currentAuth());
    }

    // ---- success -------------------------------------------------------------------------------

    @Test
    public void validTokenWithExistingMappingAuthenticates() throws Exception {
        final UserI user = enabledUser();
        when(userResolver.resolveExisting(USERNAME, PROVIDER)).thenReturn(user);
        bearer(sign(signingKey, validClaims().build()));

        doFilter();

        assertNotNull("chain should be invoked", chain.getRequest());
        final Authentication auth = currentAuth();
        assertNotNull(auth);
        assertTrue(auth instanceof OpenIdAuthToken);
        assertEquals(PROVIDER, ((OpenIdAuthToken) auth).getProviderId());
        assertNull("the bearer path must not create a session", request.getSession(false));
    }

    // ---- 401: token validity -------------------------------------------------------------------

    @Test
    public void badSignatureIsUnauthorized() throws Exception {
        bearer(sign(strangerKey, validClaims().build()));

        doFilter();

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertNull("chain must not be invoked", chain.getRequest());
        assertNull(currentAuth());
        assertTrue(response.getHeader("WWW-Authenticate").startsWith("Bearer"));
    }

    @Test
    public void unknownIssuerIsUnauthorized() throws Exception {
        bearer(sign(signingKey, validClaims().issuer("https://other.example").build()));

        doFilter();

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertNull("chain must not be invoked", chain.getRequest());
        assertNull(currentAuth());
    }

    @Test
    public void garbageBearerTokenIsUnauthorized() throws Exception {
        bearer("not-a-jwt");

        doFilter();

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertNull(chain.getRequest());
    }

    // ---- 403: authorization --------------------------------------------------------------------

    @Test
    public void failingClaimGateIsForbidden() throws Exception {
        // Enable the role gate; ClaimGateFactory reads these per call, so no rebuild needed.
        when(plugin.getProperty(PROVIDER, "bearer.roleCheck.enabled")).thenReturn("true");
        when(plugin.getProperty(PROVIDER, "roleCheck.rolePath")).thenReturn("resource_access.xnat.roles");
        when(plugin.getProperty(PROVIDER, "roleCheck.requiredRoles")).thenReturn("xnat_access");

        final Map<String, Object> xnat = new HashMap<>();
        xnat.put("roles", Arrays.asList("guest"));
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", xnat);
        bearer(sign(signingKey, validClaims().claim("resource_access", resourceAccess).build()));

        doFilter();

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertNull("chain must not be invoked", chain.getRequest());
        assertNull(currentAuth());
    }

    @Test
    public void validTokenWithNoMappingAndNoAutoCreateIsForbidden() throws Exception {
        when(userResolver.resolveExisting(USERNAME, PROVIDER))
                .thenThrow(new UsernameAuthMappingNotFoundException(USERNAME, XdatUserAuthService.OPENID, PROVIDER, null, null, null));
        bearer(sign(signingKey, validClaims().build()));

        doFilter();

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertNull("chain must not be invoked", chain.getRequest());
        assertNull(currentAuth());
    }

    @Test
    public void disabledAccountIsForbidden() throws Exception {
        final UserI disabled = mock(UserI.class);
        lenient().when(disabled.getUsername()).thenReturn(USERNAME);
        when(disabled.isEnabled()).thenReturn(false);
        when(userResolver.resolveExisting(USERNAME, PROVIDER)).thenReturn(disabled);
        bearer(sign(signingKey, validClaims().build()));

        doFilter();

        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
        assertNull(chain.getRequest());
        assertNull(currentAuth());
    }
}
