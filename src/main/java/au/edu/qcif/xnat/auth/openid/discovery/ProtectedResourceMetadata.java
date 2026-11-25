package au.edu.qcif.xnat.auth.openid.discovery;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;

/**
 * The OAuth 2.0 Protected Resource Metadata document (RFC 9728) that tells a desktop tool which
 * authorization server issues tokens XNAT accepts and which client ID the tool should use.
 *
 * <p>The {@code resource} value is always one of the configured site URLs ({@code siteUrl},
 * {@code discovery.apiUrl}, {@code discovery.webUrl}), chosen by the request's host and path, and
 * never built from the request: a client may only use the document when {@code resource} equals the
 * URL it was given, and a value derived from the {@code Host} header would let any caller choose it.</p>
 */
@Slf4j
@Component
public class ProtectedResourceMetadata {

    public static final String WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource";

    static final String ENABLED = "discovery.enabled";
    static final String PROVIDER = "discovery.provider";
    static final String RESOURCE_NAME = "discovery.resourceName";
    static final String SCOPES = "discovery.scopes";
    static final String DOCUMENTATION = "discovery.documentation";
    static final String API_URL = "discovery.apiUrl";
    static final String WEB_URL = "discovery.webUrl";
    static final String CLIENTS_PREFIX = "openid.discovery.clients.";

    private static final String DEFAULT_SCOPES = "openid";

    private final OpenIdAuthPlugin _plugin;
    private final String _issuer;

    public ProtectedResourceMetadata(final OpenIdAuthPlugin plugin) {
        _plugin = plugin;
        _issuer = resolveIssuer(plugin);
    }

    /** True when discovery is switched on and names a provider that accepts bearer tokens. */
    public boolean isEnabled() {
        return _issuer != null;
    }

    /**
     * The configured URL that a request for the well-known document addresses, or empty if discovery
     * is off or the request's host and path match none of them. When several match, the one with the
     * request's scheme and port wins, else the first.
     *
     * @param suffix the path after {@link #WELL_KNOWN_PATH}: the resource's path in the RFC 9728 form,
     *               or empty when the document was requested inside the webapp's context path.
     */
    public Optional<String> resourceFor(final HttpServletRequest request, final String suffix) {
        if (!isEnabled()) {
            return Optional.empty();
        }
        final String path = StringUtils.isEmpty(suffix) ? request.getContextPath() : suffix;
        final List<URI> matches = configuredUrls()
                .filter(url -> StringUtils.equalsIgnoreCase(url.getHost(), request.getServerName()))
                .filter(url -> StringUtils.stripEnd(url.getPath(), "/").equals(StringUtils.stripEnd(path, "/")))
                .collect(Collectors.toList());
        return matches.stream()
                .filter(url -> StringUtils.equalsIgnoreCase(url.getScheme(), request.getScheme()) && port(url) == request.getServerPort())
                .findFirst()
                .or(() -> matches.stream().findFirst())
                .map(ProtectedResourceMetadata::normalize);
    }

    private static int port(final URI url) {
        return url.getPort() != -1 ? url.getPort() : "https".equalsIgnoreCase(url.getScheme()) ? 443 : 80;
    }

    /** The well-known URL of the document describing the site this request reached, for {@code WWW-Authenticate}. */
    public Optional<String> metadataUrlFor(final HttpServletRequest request) {
        return resourceFor(request, "").map(resource -> {
            final URI uri = URI.create(resource);
            return uri.getScheme() + "://" + uri.getRawAuthority() + WELL_KNOWN_PATH + StringUtils.defaultString(uri.getRawPath());
        });
    }

    /** The metadata document for {@code resource}, in the order RFC 9728 lists the fields. */
    public Map<String, Object> document(final String resource) {
        final String siteUrl = normalizeOrNull(_plugin.getSiteUrl());
        final List<String> scopes = scopes();
        final Map<String, Object> document = new LinkedHashMap<>();
        document.put("resource", resource);
        putIfNotBlank(document, "resource_name", _plugin.getProperty(RESOURCE_NAME));
        document.put("authorization_servers", Collections.singletonList(_issuer));
        document.put("scopes_supported", scopes);
        document.put("bearer_methods_supported", Collections.singletonList("header"));
        putIfNotBlank(document, "resource_documentation", _plugin.getProperty(DOCUMENTATION));
        putIfNotBlank(document, "xnat_api_url", StringUtils.defaultIfBlank(normalizeOrNull(_plugin.getProperty(API_URL)), siteUrl));
        putIfNotBlank(document, "xnat_web_url", StringUtils.defaultIfBlank(normalizeOrNull(_plugin.getProperty(WEB_URL)), siteUrl));
        document.put("xnat_clients", clients(String.join(" ", scopes)));
        return document;
    }

    private List<String> scopes() {
        return Arrays.asList(StringUtils.split(StringUtils.defaultIfBlank(_plugin.getProperty(SCOPES), DEFAULT_SCOPES), ", "));
    }

    /** {@code openid.discovery.clients.<name>.clientId} and {@code .scope}, keyed by tool name. */
    private Map<String, Map<String, String>> clients(final String defaultScope) {
        final Map<String, Map<String, String>> clients = new TreeMap<>();
        for (final String key : _plugin.getProps().stringPropertyNames()) {
            if (!key.startsWith(CLIENTS_PREFIX) || !key.endsWith(".clientId")) {
                continue;
            }
            final String name = key.substring(CLIENTS_PREFIX.length(), key.length() - ".clientId".length());
            final String clientId = StringUtils.trimToNull(_plugin.getProps().getProperty(key));
            if (name.isEmpty() || clientId == null) {
                continue;
            }
            final Map<String, String> client = new LinkedHashMap<>();
            client.put("client_id", clientId);
            client.put("scope", StringUtils.defaultIfBlank(_plugin.getProps().getProperty(CLIENTS_PREFIX + name + ".scope"), defaultScope).trim());
            clients.put(name, client);
        }
        return clients;
    }

    private Stream<URI> configuredUrls() {
        return Stream.of(_plugin.getSiteUrl(), _plugin.getProperty(API_URL), _plugin.getProperty(WEB_URL))
                .filter(StringUtils::isNotBlank)
                .map(ProtectedResourceMetadata::parse)
                .filter(Objects::nonNull);
    }

    private static URI parse(final String url) {
        try {
            final URI uri = URI.create(url.trim());
            return uri.getScheme() != null && uri.getHost() != null ? uri : null;
        } catch (IllegalArgumentException e) {
            log.warn("Ignoring '{}' for protected resource metadata: not a URL", url);
            return null;
        }
    }

    private static String normalize(final URI uri) {
        return StringUtils.stripEnd(uri.getScheme() + "://" + uri.getRawAuthority() + StringUtils.defaultString(uri.getRawPath()), "/");
    }

    private static String normalizeOrNull(final String url) {
        final URI uri = StringUtils.isBlank(url) ? null : parse(url);
        return uri == null ? null : normalize(uri);
    }

    private static void putIfNotBlank(final Map<String, Object> document, final String field, final String value) {
        if (StringUtils.isNotBlank(value)) {
            document.put(field, value.trim());
        }
    }

    private static String resolveIssuer(final OpenIdAuthPlugin plugin) {
        if (!Boolean.parseBoolean(plugin.getProperty(ENABLED))) {
            return null;
        }
        final String providerId = StringUtils.trimToNull(plugin.getProperty(PROVIDER));
        if (providerId == null) {
            log.error("openid.{} is true but openid.{} is not set; protected resource metadata is not served", ENABLED, PROVIDER);
            return null;
        }
        final boolean bearerProvider = plugin.isEnabled(providerId)
                && Boolean.parseBoolean(plugin.getProperty(providerId, "bearer.enabled"))
                && StringUtils.isNotBlank(plugin.getProperty(providerId, ISSUER))
                && StringUtils.isNotBlank(plugin.getProperty(providerId, JWKS_URI));
        if (!bearerProvider) {
            log.error("openid.{} names provider '{}', which is not an enabled provider with bearer.enabled=true, "
                    + "issuer and jwksUri; protected resource metadata is not served", PROVIDER, providerId);
            return null;
        }
        return plugin.getProperty(providerId, ISSUER).trim();
    }
}
