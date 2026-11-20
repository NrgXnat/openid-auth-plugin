package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import au.edu.qcif.xnat.auth.openid.gate.RoleSync;
import au.edu.qcif.xnat.auth.openid.gate.TokenContext;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.UserHelper;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.nrg.xft.security.UserI;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;

import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Where role sync sits in a browser sign-in: after every check that can refuse the account, and with
 * the user it returns as the one who is signed in.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectFilterRoleSyncTest {

    private static final String PROVIDER = "keycloak";
    private static final String USERNAME = "keycloak_alice"; // default pattern [providerId]_[sub], sub="alice"
    private static final String SERVER   = "https://xnat.example";

    @Mock private OpenIdAuthPlugin             plugin;
    @Mock private AuthenticationEventPublisher eventPublisher;
    @Mock private SiteConfigPreferences        siteConfigPreferences;
    @Mock private KeystoreService              keystoreService;
    @Mock private OpenIdUserResolver           userResolver;
    @Mock private RoleSync                     roleSync;

    private OpenIdConnectFilter     filter;
    private MockHttpServletRequest  request;
    private MockHttpServletResponse response;
    private UserI                   account;

    @Before
    public void setUp() throws Exception {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.isEnabled(PROVIDER)).thenReturn(true);
        filter = new OpenIdConnectFilter(plugin, eventPublisher, siteConfigPreferences, keystoreService, userResolver, roleSync) {
            @Override String fullServerPath() { return SERVER; }
        };

        // The provider's token response, carrying an ID token. No issuer or jwksUri is set, so the ID token
        // is read without validation and any signature will do.
        final SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
                .subject("alice")
                .claim("groups", Collections.singletonList("xnat-admin"))
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build());
        idToken.sign(new MACSigner("0123456789abcdef0123456789abcdef"));
        final DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("access-token");
        accessToken.setAdditionalInformation(Collections.singletonMap("id_token", idToken.serialize()));
        final OAuth2RestTemplate restTemplate = mock(OAuth2RestTemplate.class);
        lenient().when(restTemplate.getAccessToken()).thenReturn(accessToken);
        filter.setOAuth2RestTemplate(restTemplate);

        request = new MockHttpServletRequest("GET", "/openid-login");
        request.getSession().setAttribute("providerId", PROVIDER);
        response = new MockHttpServletResponse();

        account = mock(UserI.class);
        lenient().when(account.getUsername()).thenReturn(USERNAME);
        lenient().when(account.getEmail()).thenReturn("alice@example.org");
        lenient().when(account.isEnabled()).thenReturn(true);
        lenient().when(account.isAccountNonLocked()).thenReturn(true);
        lenient().when(userResolver.resolveExisting(USERNAME, PROVIDER)).thenReturn(account);
    }

    @Test
    public void theUserRoleSyncReturnsIsTheOneSignedIn() throws Exception {
        // Role sync reloads the user when it changes a role, so the session starts with the new roles.
        final UserI reloaded = mock(UserI.class);
        lenient().when(reloaded.getUsername()).thenReturn(USERNAME);
        when(roleSync.apply(eq(PROVIDER), eq(AuthPath.ID_TOKEN), any(TokenContext.class), eq(account))).thenReturn(reloaded);

        final Authentication authentication;
        // The sign-in's last steps record the user through XNAT's static helper, which needs a running XNAT.
        try (final MockedStatic<UserHelper> userHelper = mockStatic(UserHelper.class)) {
            authentication = filter.attemptAuthentication(request, response);
        }

        assertSame(reloaded, authentication.getPrincipal());
        verify(roleSync).apply(eq(PROVIDER), eq(AuthPath.ID_TOKEN),
                org.mockito.ArgumentMatchers.argThat(token ->
                        Collections.singletonList("xnat-admin").equals(token.claims().getClaim("groups"))),
                eq(account));
    }

    @Test
    public void aDisabledAccountIsRefusedBeforeRoleSync() {
        when(account.isEnabled()).thenReturn(false);

        assertThrows(NewAutoAccountNotAutoEnabledException.class, () -> filter.attemptAuthentication(request, response));

        verify(roleSync, never()).apply(any(), any(), any(), any());
    }

    @Test
    public void anUnverifiedAccountIsSentToVerificationBeforeRoleSync() throws Exception {
        when(siteConfigPreferences.getEmailVerification()).thenReturn(true);
        when(account.isVerified()).thenReturn(false);

        assertNull(filter.attemptAuthentication(request, response));

        verify(roleSync, never()).apply(any(), any(), any(), any());
    }

    @Test
    public void aLockedAccountIsRefusedBeforeRoleSync() {
        when(account.isAccountNonLocked()).thenReturn(false);

        assertThrows(CredentialsExpiredException.class, () -> filter.attemptAuthentication(request, response));

        verify(roleSync, never()).apply(any(), any(), any(), any());
    }
}
