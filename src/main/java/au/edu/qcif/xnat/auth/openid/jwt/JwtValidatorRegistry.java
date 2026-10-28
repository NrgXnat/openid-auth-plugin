package au.edu.qcif.xnat.auth.openid.jwt;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ID_TOKEN_ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;

/**
 * Each provider's {@link JwtValidator} for each path. A provider's validators share one key set, so it is
 * fetched and cached once. ID tokens are checked against {@code idToken.issuer} when set, else {@code issuer}.
 */
@Slf4j
@Component
public class JwtValidatorRegistry {

    private final Map<String, JwtValidator> bearerValidators = new HashMap<>();
    private final Map<String, JwtValidator> idTokenValidators = new HashMap<>();

    @Autowired
    public JwtValidatorRegistry(final OpenIdAuthPlugin plugin) {
        for (final String providerId : plugin.getEnabledProviders()) {
            final String issuer = StringUtils.trimToNull(plugin.getProperty(providerId, ISSUER));
            final String idTokenIssuer = StringUtils.defaultIfBlank(
                    StringUtils.trim(plugin.getProperty(providerId, ID_TOKEN_ISSUER)), issuer);
            final String jwksUri = StringUtils.trimToNull(plugin.getProperty(providerId, JWKS_URI));
            if (idTokenIssuer == null || jwksUri == null) {
                continue;
            }
            final JWKSource<SecurityContext> keys;
            try {
                keys = JwtValidator.remoteJwks(new URI(jwksUri).toURL());
            } catch (final URISyntaxException | MalformedURLException | IllegalArgumentException e) {
                log.error("Provider '{}' has a malformed jwksUri '{}'; its tokens cannot be validated.",
                        providerId, jwksUri, e);
                continue;
            }
            idTokenValidators.put(providerId, new JwtValidator(idTokenIssuer, keys));
            if (issuer != null) {
                bearerValidators.put(providerId, new JwtValidator(issuer, keys));
            }
        }
    }

    /** Uses the same validators on both paths. */
    public JwtValidatorRegistry(final Map<String, JwtValidator> validators) {
        bearerValidators.putAll(validators);
        idTokenValidators.putAll(validators);
    }

    /** The provider's validator for this path, or {@code null} if it has no valid issuer and {@code jwksUri}. */
    public JwtValidator get(final String providerId, final AuthPath path) {
        return (path == AuthPath.BEARER ? bearerValidators : idTokenValidators).get(providerId);
    }
}
