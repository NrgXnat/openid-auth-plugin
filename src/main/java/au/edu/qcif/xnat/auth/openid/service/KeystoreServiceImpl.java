package au.edu.qcif.xnat.auth.openid.service;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.preferences.OpenIdPreferences;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xapi.exceptions.NotFoundException;
import org.nrg.xnat.services.XnatAppInfo;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
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

    // Key generation constants
    private static final int RSA_KEY_SIZE = 2048;

    // Retry constants for non-primary nodes waiting for key generation
    private static final int MAX_KEY_WAIT_ATTEMPTS = 30;
    private static final long INITIAL_RETRY_DELAY_MS = 100;
    private static final long MAX_RETRY_DELAY_MS = 5000;

    private final Map<String, JWK> jwks;
    private final OpenIdAuthPlugin openIdAuthPlugin;
    private final OpenIdPreferences openIdPreferences;
    private final XnatAppInfo xnatAppInfo;

    public KeystoreServiceImpl(final OpenIdAuthPlugin openIdAuthPlugin,
                               final OpenIdPreferences openIdPreferences,
                               final XnatAppInfo xnatAppInfo) {
        this.openIdAuthPlugin = openIdAuthPlugin;
        this.openIdPreferences = openIdPreferences;
        this.xnatAppInfo = xnatAppInfo;
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
        final Map<String, JWK> initializedKeys = configuredAlgorithms.stream()
                .map(alg -> {
                    try {
                        final JWEAlgorithm jweAlg = JWEAlgorithm.parse(alg);
                        JWK key;

                        // First, attempt to load key from database preferences
                        if (openIdPreferences.hasJwk(alg)) {
                            log.info("Loading existing JWK for algorithm {} from database", alg);
                            try {
                                final String jwkJson = openIdPreferences.getJwk(alg);
                                key = JWK.parse(jwkJson);

                                // Validate that the loaded key matches the expected algorithm
                                if (!validateKeyAlgorithm(key, jweAlg)) {
                                    log.warn("Stored JWK for algorithm {} does not match expected algorithm, regenerating", alg);
                                    key = generateAndPersistKey(alg, jweAlg);
                                } else {
                                    log.info("Successfully loaded and validated JWK for algorithm {}", alg);
                                }
                            } catch (ParseException e) {
                                log.error("Failed to parse stored JWK for algorithm {}, regenerating", alg, e);
                                key = generateAndPersistKey(alg, jweAlg);
                            }
                        } else {
                            // No key exists, generate and persist new key
                            log.info("No existing JWK found for algorithm {}, generating new key", alg);
                            key = generateAndPersistKey(alg, jweAlg);
                        }

                        return new AbstractMap.SimpleEntry<>(alg, key);
                    } catch (Exception e) {
                        log.error("Failed to initialize encryption key for algorithm {}. " +
                                "This algorithm will not be available for ID token encryption.",
                                alg, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        // Report summary of initialization
        if (initializedKeys.isEmpty() && !configuredAlgorithms.isEmpty()) {
            log.error("No encryption keys were successfully initialized. Configured algorithms: {}",
                    configuredAlgorithms);
        } else if (initializedKeys.size() < configuredAlgorithms.size()) {
            final Set<String> failedAlgorithms = configuredAlgorithms.stream()
                    .filter(alg -> !initializedKeys.containsKey(alg))
                    .collect(Collectors.toSet());
            log.warn("Some encryption keys failed to initialize. Successfully initialized: {}, Failed: {}",
                    initializedKeys.keySet(), failedAlgorithms);
        } else {
            log.info("Successfully initialized all encryption keys for algorithms: {}", initializedKeys.keySet());
        }

        return initializedKeys;
    }

    /**
     * Generates a new encryption key for the specified algorithm and persists it to the database.
     * Only the primary node generates keys to avoid race conditions in load-balanced environments.
     * Non-primary nodes will wait and retry loading from the database.
     *
     * @param algorithm The algorithm name (e.g., "RSA-OAEP-256")
     * @param jweAlg The parsed JWE algorithm
     * @return The generated JWK
     * @throws Exception if key generation fails
     */
    private JWK generateAndPersistKey(final String algorithm, final JWEAlgorithm jweAlg) throws Exception {
        if (!JWEAlgorithm.Family.RSA.contains(jweAlg)) {
            log.warn("Unsupported algorithm {}, skipping key generation", algorithm);
            return null;
        }

        // Only the primary node should generate keys
        if (xnatAppInfo.isPrimaryNode()) {
            log.info("Primary node generating new JWK for algorithm {}", algorithm);

            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(RSA_KEY_SIZE);

            final KeyPair keyPair = kpg.generateKeyPair();
            final JWK key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey(keyPair.getPrivate())
                    .algorithm(jweAlg)
                    .keyUse(KeyUse.ENCRYPTION)
                    .keyIDFromThumbprint()
                    .build();

            // Persist the generated key to database
            final String jwkJson = key.toJSONString();
            openIdPreferences.setJwk(algorithm, jwkJson);
            log.info("Primary node generated and persisted new JWK for algorithm {}", algorithm);

            return key;
        } else {
            // Non-primary node: wait for primary to generate and persist the key
            log.info("Non-primary node waiting for primary to generate JWK for algorithm {}", algorithm);
            return waitForKeyFromPrimary(algorithm, jweAlg);
        }
    }

    /**
     * Waits for the primary node to generate and persist a key to the database.
     * Retries with exponential backoff up to a maximum number of attempts.
     *
     * @param algorithm The algorithm name
     * @param jweAlg The parsed JWE algorithm
     * @return The loaded JWK from the database
     * @throws Exception if the key is not available after all retry attempts
     */
    private JWK waitForKeyFromPrimary(final String algorithm, final JWEAlgorithm jweAlg) throws Exception {
        for (int attempt = 1; attempt <= MAX_KEY_WAIT_ATTEMPTS; attempt++) {
            if (openIdPreferences.hasJwk(algorithm)) {
                try {
                    final String jwkJson = openIdPreferences.getJwk(algorithm);
                    final JWK key = JWK.parse(jwkJson);

                    if (validateKeyAlgorithm(key, jweAlg)) {
                        log.info("Non-primary node successfully loaded JWK for algorithm {} from database (attempt {})", algorithm, attempt);
                        return key;
                    } else {
                        log.warn("Loaded JWK for algorithm {} does not match expected algorithm (attempt {})", algorithm, attempt);
                    }
                } catch (ParseException e) {
                    log.warn("Failed to parse JWK for algorithm {} (attempt {})", algorithm, attempt, e);
                }
            }

            // Exponential backoff with cap
            final long delayMs = Math.min(INITIAL_RETRY_DELAY_MS * (1L << (attempt - 1)), MAX_RETRY_DELAY_MS);
            log.debug("Non-primary node waiting {}ms for primary to generate JWK for algorithm {} (attempt {}/{})",
                     delayMs, algorithm, attempt, MAX_KEY_WAIT_ATTEMPTS);

            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new KeyGenerationTimeoutException("Interrupted while waiting for primary node to generate key for algorithm " + algorithm, e);
            }
        }

        throw new KeyGenerationTimeoutException("Timeout waiting for primary node to generate key for algorithm " + algorithm +
                          " after " + MAX_KEY_WAIT_ATTEMPTS + " attempts");
    }

    /**
     * Validates that a loaded JWK matches the expected algorithm.
     *
     * @param key The JWK to validate
     * @param expectedAlgorithm The expected JWE algorithm
     * @return true if the key matches the expected algorithm, false otherwise
     */
    private boolean validateKeyAlgorithm(final JWK key, final JWEAlgorithm expectedAlgorithm) {
        if (key == null || key.getAlgorithm() == null || expectedAlgorithm == null) {
            return false;
        }
        return key.getAlgorithm().equals(expectedAlgorithm);
    }
}
