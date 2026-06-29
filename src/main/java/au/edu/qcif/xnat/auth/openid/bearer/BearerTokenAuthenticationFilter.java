package au.edu.qcif.xnat.auth.openid.bearer;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.OpenIdConnectUserDetails;
import au.edu.qcif.xnat.auth.openid.OpenIdUserResolver;
import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGate;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateException;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URISyntaxException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;

/**
 * Authenticates REST callers that present {@code Authorization: Bearer <jwt>}, where the JWT is an
 * access token minted by a configured OpenID provider. Unlike the interactive ID-token path, a
 * bearer token arrives from an untrusted client, so it is fully validated (signature, issuer,
 * expiry) before the request is trusted.
 *
 * <p>Flow ({@code doFilterInternal}):</p>
 * <ol>
 *   <li>If the {@link SecurityContextHolder} already holds an authenticated principal (e.g. an
 *       upstream session or basic-auth filter already won), pass through untouched.</li>
 *   <li>If there is no {@code Bearer} header, pass through (the request is for some other
 *       authentication mechanism).</li>
 *   <li>Peek the unverified {@code iss}, route it to a configured provider, and validate the token
 *       with that provider's keys. A bad/expired/wrong-issuer/unknown-issuer token → <b>401</b>.</li>
 *   <li>Run the provider's bearer claim gates; a gate failure → <b>403</b>.</li>
 *   <li>Resolve (and optionally auto-create) the XNAT user; a missing mapping with auto-create off,
 *       a disabled or locked account, or an unresolvable identity → <b>403</b>.</li>
 *   <li>On success, set the {@link SecurityContextHolder} authentication and continue the chain.</li>
 * </ol>
 *
 * <p><b>Stateless by design.</b> XNAT runs {@code SessionCreationPolicy.IF_REQUIRED} with the
 * default {@code HttpSessionSecurityContextRepository}, so simply placing a non-anonymous
 * {@code Authentication} in the {@code SecurityContext} would normally cause Spring Security's
 * {@code SecurityContextPersistenceFilter} to create a {@code JSESSIONID} at the end of the request.
 * To stay stateless the filter authenticates with a {@link BearerAuthToken}, which is annotated
 * {@link org.springframework.security.core.Transient @Transient}; the repository's {@code saveContext}
 * skips persisting a transient authentication, so it creates no session. The filter also deliberately
 * does <em>not</em> populate the session-scoped {@code UserHelper} — doing so would force a session —
 * so authorization relies on the Spring {@code SecurityContext} principal alone.</p>
 *
 * <p>The {@code @Transient} token only governs {@code SecurityContextPersistenceFilter}, though.
 * Other downstream filters create sessions of their own accord — notably XNAT's
 * {@code XnatExpiredPasswordFilter}, which calls {@code request.getSession()} unconditionally on every
 * request and so makes the container mint a {@code JSESSIONID}. To close that path the successful
 * branch continues the chain behind a {@link StatelessSessionRequestWrapper}, which serves a
 * per-request {@link EphemeralHttpSession} for {@code getSession(true)} but never registers a session
 * with the container, so no cookie is written.</p>
 *
 * <p><b>Why stateless, and what it means for authorization.</b> A bearer access token is a
 * self-contained, per-request credential; the caller re-presents it on every request, so a
 * server-side session adds nothing but cost and surprise (a stray {@code JSESSIONID} the client never
 * asked for, plus the memory and fixation surface of a session per API call). Statelessness is safe
 * because XNAT's authorization does not depend on the session: across the Restlet ({@code /data}),
 * XAPI ({@code /xapi}), and Turbine layers, the acting user is resolved per-request from the
 * {@code SecurityContextHolder} (via {@code XDAT.getUserDetails()}) and permissions are evaluated from
 * a username-keyed, application-scoped cache — never read out of the {@code HttpSession}. A bearer
 * request therefore authorizes identically to a session-backed login, for reads and writes alike. The
 * one session-coupled behavior in XNAT is the CSRF token check on legacy {@code /app} Turbine actions,
 * which is orthogonal to the authorization decision and is bypassed for non-browser user agents, so it
 * does not affect bearer/API callers.</p>
 */
@Slf4j
@Component
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final OpenIdAuthPlugin _plugin;
    private final BearerTokenExtractor _extractor;
    private final BearerProviderResolver _providerResolver;
    private final Map<String, BearerTokenValidator> _validators;
    private final ClaimGateFactory _gateFactory;
    private final OpenIdUserResolver _userResolver;

    @Autowired
    public BearerTokenAuthenticationFilter(final OpenIdAuthPlugin plugin,
                                           final XdatUserAuthService userAuthService) {
        this(plugin, new BearerTokenExtractor(), new BearerProviderResolver(plugin), buildValidators(plugin),
                new ClaimGateFactory(plugin), new OpenIdUserResolver(plugin, userAuthService));
    }

    /** Test seam: inject pre-built collaborators (offline validators, fake resolvers). */
    BearerTokenAuthenticationFilter(final OpenIdAuthPlugin plugin,
                                    final BearerTokenExtractor extractor,
                                    final BearerProviderResolver providerResolver,
                                    final Map<String, BearerTokenValidator> validators,
                                    final ClaimGateFactory gateFactory,
                                    final OpenIdUserResolver userResolver) {
        _plugin = plugin;
        _extractor = extractor;
        _providerResolver = providerResolver;
        _validators = validators;
        _gateFactory = gateFactory;
        _userResolver = userResolver;
    }

    /** Builds one cached validator per eligible provider; a malformed jwksUri excludes that provider. */
    private static Map<String, BearerTokenValidator> buildValidators(final OpenIdAuthPlugin plugin) {
        final Map<String, BearerTokenValidator> validators = new LinkedHashMap<>();
        for (final String providerId : new BearerProviderResolver(plugin).providerIds()) {
            final String issuer = plugin.getProperty(providerId, ISSUER);
            final String jwksUri = plugin.getProperty(providerId, JWKS_URI);
            try {
                validators.put(providerId, BearerTokenValidator.forRemoteJwks(issuer, (new URI(jwksUri)).toURL()));
            } catch (final MalformedURLException | URISyntaxException e) {
                log.error("Provider '{}' has a malformed jwksUri '{}' — the bearer path is disabled for it.",
                        providerId, jwksUri, e);
            }
        }
        return validators;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        // A request already authenticated upstream (session cookie, basic auth) skips the bearer
        // pipeline entirely — don't re-validate and don't make a session.
        final Authentication current = SecurityContextHolder.getContext().getAuthentication();
        if (current != null && current.isAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }

        final Optional<String> maybeToken = _extractor.extract(request);
        if (maybeToken.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        final String rawJwt = maybeToken.get();

        // Read the unverified issuer only to select which provider's keys to validate against; the
        // validator re-checks iss cryptographically, so a forged iss cannot pick a weaker provider.
        final String issuer;
        try {
            issuer = SignedJWT.parse(rawJwt).getJWTClaimsSet().getIssuer();
        } catch (final ParseException e) {
            unauthorized(response, "malformed bearer token");
            return;
        }

        final Optional<String> maybeProvider = _providerResolver.resolve(issuer);
        if (maybeProvider.isEmpty()) {
            log.info("Bearer token from unknown issuer '{}' rejected", issuer);
            unauthorized(response, "bearer token issuer is not configured");
            return;
        }
        final String providerId = maybeProvider.get();

        final BearerTokenValidator validator = _validators.get(providerId);
        if (validator == null) {
            // Provider routed but no validator built (e.g. malformed jwksUri at startup) — fail closed.
            log.warn("No bearer token validator configured for provider '{}'", providerId);
            unauthorized(response, "bearer token issuer is not configured");
            return;
        }

        final JWTClaimsSet claims;
        try {
            claims = validator.validate(rawJwt);
        } catch (final BearerTokenValidationException e) {
            log.info("Bearer token for provider '{}' failed validation: {}", providerId, e.getMessage());
            unauthorized(response, "invalid bearer token");
            return;
        }

        try {
            applyBearerClaimGates(providerId, claims);
        } catch (final ClaimGateException e) {
            log.info("Bearer claim gate rejected token for provider '{}': {}", providerId, e.getMessage());
            forbidden(response, e.getMessage());
            return;
        }

        final OpenIdConnectUserDetails user;
        try {
            user = buildUserDetails(providerId, claims);
        } catch (final IllegalArgumentException e) {
            log.warn("Could not resolve a username for a bearer token from provider '{}': {}", providerId, e.getMessage());
            forbidden(response, "could not resolve an XNAT identity from the token");
            return;
        }

        final UserI xdatUser = resolveUser(providerId, user, response);
        if (xdatUser == null) {
            return; // resolveUser already wrote the 403
        }
        if (!xdatUser.isEnabled()) {
            forbidden(response, "the XNAT account for this identity is not enabled");
            return;
        }
        if (!xdatUser.isAccountNonLocked()) {
            forbidden(response, "the XNAT account for this identity is locked");
            return;
        }

        final Authentication authentication = new BearerAuthToken(xdatUser, providerId);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug("Bearer token authenticated user '{}' for provider '{}'", xdatUser.getUsername(), providerId);
        // Run the rest of the chain behind a wrapper that refuses to create a container session, so
        // downstream filters that call request.getSession() (e.g. XNAT's XnatExpiredPasswordFilter)
        // cannot make the container mint a JSESSIONID for this stateless, token-authenticated request.
        chain.doFilter(new StatelessSessionRequestWrapper(request), response);
    }

    /**
     * Runs the bearer-path claim gates against the validated claims. A gate failure throws
     * {@link ClaimGateException}, which the filter maps to 403. With no bearer gates enabled this is
     * a no-op. Package-private so it can be unit-tested directly.
     */
    void applyBearerClaimGates(final String providerId, final JWTClaimsSet claims) throws ClaimGateException {
        for (final ClaimGate gate : _gateFactory.gatesFor(providerId, AuthPath.BEARER)) {
            gate.check(claims);
        }
    }

    /** Looks up the mapped XNAT user, auto-creating it when configured; writes 403 and returns null on failure. */
    private UserI resolveUser(final String providerId, final OpenIdConnectUserDetails user,
                              final HttpServletResponse response) throws IOException {
        try {
            return _userResolver.resolveExisting(user.getUsername(), providerId);
        } catch (final UsernameAuthMappingNotFoundException notFound) {
            if (!isForceUserCreate(providerId)) {
                log.info("No XNAT account mapped to '{}' for provider '{}' and auto-create is off; denying",
                        user.getUsername(), providerId);
                forbidden(response, "no XNAT account is mapped to this OpenID identity");
                return null;
            }
            try {
                return _userResolver.createUser(providerId, user);
            } catch (final AuthenticationException e) {
                log.warn("Failed to auto-create an XNAT account for '{}' on the bearer path", user.getUsername(), e);
                forbidden(response, "could not provision an XNAT account for this identity");
                return null;
            }
        }
    }

    /** Flattens the validated claims and resolves the username via the provider's usernamePattern. */
    private OpenIdConnectUserDetails buildUserDetails(final String providerId, final JWTClaimsSet claims) {
        final Map<String, String> authInfo = claims.getClaims().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue() != null ? e.getValue().toString() : ""));
        return new OpenIdConnectUserDetails(providerId, authInfo, null, _plugin);
    }

    /** {@code bearer.forceUserCreate} if set, otherwise the shared {@code forceUserCreate}. */
    private boolean isForceUserCreate(final String providerId) {
        final String perPath = _plugin.getProperty(providerId, "bearer.forceUserCreate");
        final String value = StringUtils.isNotBlank(perPath) ? perPath : _plugin.getProperty(providerId, "forceUserCreate");
        return Boolean.parseBoolean(value);
    }

    private void unauthorized(final HttpServletResponse response, final String message) throws IOException {
        SecurityContextHolder.clearContext();
        response.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    private void forbidden(final HttpServletResponse response, final String message) throws IOException {
        SecurityContextHolder.clearContext();
        response.sendError(HttpServletResponse.SC_FORBIDDEN, message);
    }
}
