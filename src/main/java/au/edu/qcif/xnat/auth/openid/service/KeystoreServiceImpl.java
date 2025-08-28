package au.edu.qcif.xnat.auth.openid.service;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xapi.exceptions.NotFoundException;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
public class KeystoreServiceImpl implements KeystoreService {

    public static final String ID_TOKEN_ENCRYPTION_ALG_PROPERTY = "idTokenEncryptionAlgorithm";

    private final Map<String, JWK> jwks;
    private final OpenIdAuthPlugin openIdAuthPlugin;

    public KeystoreServiceImpl(final OpenIdAuthPlugin openIdAuthPlugin) {
        this.openIdAuthPlugin = openIdAuthPlugin;
        jwks = initKeys();
    }

    @Override
    public PrivateKey getEncryptionPrivateKey(final String providerId) throws JOSEException, NotFoundException {
        final String providersAlgorithm = openIdAuthPlugin.getProperty(providerId, ID_TOKEN_ENCRYPTION_ALG_PROPERTY);
        final JWK jwk = jwks.get(providersAlgorithm);
        if (jwk == null) {
            throw new NotFoundException(ID_TOKEN_ENCRYPTION_ALG_PROPERTY + " has not been configured for " + providerId);
        }

        if (jwk instanceof RSAKey) {
            return ((RSAKey) jwk).toPrivateKey();
        } else {
            throw new JOSEException("Unsupported algorithm: " + jwk.getClass());
        }
    }

    @Override
    public JWKSet getJwks() {
        return new JWKSet(new ArrayList<>(jwks.values()));
    }

    private Map<String, JWK> initKeys() {
        final Set<String> configuredAlgorithms = openIdAuthPlugin.getAllConfiguredIdTokenEncryptionAlgorithms();
        return configuredAlgorithms.stream()
                .map(alg -> {
                    try {
                        final JWEAlgorithm jweAlg = JWEAlgorithm.parse(alg);
                        JWK key;

                        if (JWEAlgorithm.Family.RSA.contains(jweAlg)) {
                            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                            kpg.initialize(2048);

                            final KeyPair keyPair = kpg.generateKeyPair();
                            key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                                    .privateKey(keyPair.getPrivate())
                                    .algorithm(jweAlg)
                                    .keyUse(KeyUse.ENCRYPTION)
                                    .keyIDFromThumbprint()
                                    .build();

                        } else {
                            log.warn("Unsupported algorithm {}, skipping key generation", alg);
                            return null;
                        }

                        return new AbstractMap.SimpleEntry<>(alg, key);
                    } catch (Exception e) {
                        log.error("Unable to generate key for algorithm {}", alg, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
