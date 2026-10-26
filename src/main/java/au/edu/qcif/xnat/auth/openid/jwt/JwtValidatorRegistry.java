package au.edu.qcif.xnat.auth.openid.jwt;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;

/**
 * One {@link JwtValidator} per provider with a valid {@code issuer} and {@code jwksUri}, shared by the
 * interactive and bearer paths so each provider's key set is fetched and cached once.
 */
@Slf4j
@Component
public class JwtValidatorRegistry {

    private final Map<String, JwtValidator> validators;

    @Autowired
    public JwtValidatorRegistry(final OpenIdAuthPlugin plugin) {
        this(build(plugin));
    }

    public JwtValidatorRegistry(final Map<String, JwtValidator> validators) {
        this.validators = validators;
    }

    /** The provider's validator, or {@code null} if it has no valid {@code issuer} and {@code jwksUri}. */
    public JwtValidator get(final String providerId) {
        return validators.get(providerId);
    }

    private static Map<String, JwtValidator> build(final OpenIdAuthPlugin plugin) {
        final Map<String, JwtValidator> validators = new HashMap<>();
        for (final String providerId : plugin.getEnabledProviders()) {
            final String issuer = StringUtils.trimToNull(plugin.getProperty(providerId, ISSUER));
            final String jwksUri = StringUtils.trimToNull(plugin.getProperty(providerId, JWKS_URI));
            if (issuer == null || jwksUri == null) {
                continue;
            }
            try {
                validators.put(providerId, JwtValidator.forRemoteJwks(issuer, new URI(jwksUri).toURL()));
            } catch (final URISyntaxException | MalformedURLException | IllegalArgumentException e) {
                log.error("Provider '{}' has a malformed jwksUri '{}'; its tokens cannot be validated.",
                        providerId, jwksUri, e);
            }
        }
        return validators;
    }
}
