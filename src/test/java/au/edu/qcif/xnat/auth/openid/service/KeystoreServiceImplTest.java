package au.edu.qcif.xnat.auth.openid.service;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.preferences.OpenIdPreferences;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xapi.exceptions.NotFoundException;
import org.nrg.xnat.services.XnatAppInfo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class KeystoreServiceImplTest {

    @Mock
    private OpenIdAuthPlugin mockPlugin;

    @Mock
    private OpenIdPreferences mockPreferences;

    @Mock
    private XnatAppInfo mockXnatAppInfo;

    private KeystoreServiceImpl keystoreService;

    private static final String TEST_PROVIDER_ID = "keycloak";
    private static final String TEST_ALGORITHM = "RSA-OAEP-256";

    @Before
    public void setUp() {
        // Reset mocks before each test
        reset(mockPlugin, mockPreferences, mockXnatAppInfo);
        // By default, assume this is the primary node
        when(mockXnatAppInfo.isPrimaryNode()).thenReturn(true);
    }

    @Test
    public void testInitKeys_GeneratesNewKeyWhenNoneExists() {
        // Given: No existing keys in preferences
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(false);

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: A new key should be generated and persisted
        ArgumentCaptor<String> algorithmCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> jwkJsonCaptor = ArgumentCaptor.forClass(String.class);

        verify(mockPreferences).setJwk(algorithmCaptor.capture(), jwkJsonCaptor.capture());
        assertEquals(TEST_ALGORITHM, algorithmCaptor.getValue());
        assertNotNull(jwkJsonCaptor.getValue());
        assertTrue(jwkJsonCaptor.getValue().contains("\"kty\":\"RSA\""));
    }

    @Test
    public void testInitKeys_LoadsExistingKeyFromDatabase() throws Exception {
        // Given: An existing key in preferences
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(true);

        // Generate a valid RSA key for testing
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAKey testKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                .keyIDFromThumbprint()
                .build();
        String existingJwkJson = testKey.toJSONString();

        when(mockPreferences.getJwk(TEST_ALGORITHM)).thenReturn(existingJwkJson);

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: Existing key should be loaded, not generated
        verify(mockPreferences, never()).setJwk(any(), any());
        verify(mockPreferences, times(1)).hasJwk(TEST_ALGORITHM);
        verify(mockPreferences, times(1)).getJwk(TEST_ALGORITHM);
    }

    @Test
    public void testInitKeys_RegeneratesKeyWhenAlgorithmMismatch() throws Exception {
        // Given: An existing key with wrong algorithm
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(true);

        // Generate a key with different algorithm (RSA1_5 instead of RSA-OAEP-256)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAKey wrongKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .algorithm(JWEAlgorithm.RSA1_5)  // Wrong algorithm
                .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                .keyIDFromThumbprint()
                .build();
        String wrongJwkJson = wrongKey.toJSONString();

        when(mockPreferences.getJwk(TEST_ALGORITHM)).thenReturn(wrongJwkJson);

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: New key with correct algorithm should be generated
        verify(mockPreferences, times(1)).setJwk(eq(TEST_ALGORITHM), any());
    }

    @Test
    public void testInitKeys_HandlesMultipleAlgorithms() {
        // Given: Multiple algorithms configured
        Set<String> algorithms = new HashSet<>();
        algorithms.add("RSA-OAEP-256");
        algorithms.add("RSA-OAEP-384");
        algorithms.add("RSA-OAEP-512");

        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(any())).thenReturn(false);

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: Keys should be generated for all algorithms
        verify(mockPreferences, times(3)).setJwk(any(), any());
        verify(mockPreferences).setJwk(eq("RSA-OAEP-256"), any());
        verify(mockPreferences).setJwk(eq("RSA-OAEP-384"), any());
        verify(mockPreferences).setJwk(eq("RSA-OAEP-512"), any());
    }

    @Test
    public void testGetEncryptionPrivateKey_ReturnsCorrectKey() throws Exception {
        // Given: Service initialized with a key
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(false);
        when(mockPlugin.getProperty(TEST_PROVIDER_ID, KeystoreServiceImpl.ID_TOKEN_ENCRYPTION_ALG_PROPERTY))
                .thenReturn(TEST_ALGORITHM);

        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // When: Requesting private key for provider
        PrivateKey privateKey = keystoreService.getEncryptionPrivateKey(TEST_PROVIDER_ID);

        // Then: Should return a valid private key
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @Test(expected = NotFoundException.class)
    public void testGetEncryptionPrivateKey_ThrowsNotFoundForUnconfiguredAlgorithm() throws Exception {
        // Given: Service initialized without algorithm for provider
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(false);
        when(mockPlugin.getProperty(TEST_PROVIDER_ID, KeystoreServiceImpl.ID_TOKEN_ENCRYPTION_ALG_PROPERTY))
                .thenReturn("RSA-OAEP-512");  // Different algorithm not initialized

        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // When/Then: Should throw NotFoundException
        keystoreService.getEncryptionPrivateKey(TEST_PROVIDER_ID);
    }

    @Test
    public void testGetJwks_ReturnsPublicKeysOnly() throws Exception {
        // Given: Service initialized with keys
        Set<String> algorithms = new HashSet<>();
        algorithms.add("RSA-OAEP-256");
        algorithms.add("RSA-OAEP-384");

        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(any())).thenReturn(false);

        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // When: Requesting JWKS
        JWKSet jwks = keystoreService.getJwks();

        // Then: Should return public keys only
        assertNotNull(jwks);
        assertEquals(2, jwks.getKeys().size());

        for (JWK key : jwks.getKeys()) {
            assertTrue(key instanceof RSAKey);
            RSAKey rsaKey = (RSAKey) key;
            // Public key should be present
            assertNotNull(rsaKey.toPublicJWK());
            // Verify it's a public-only key (no private components)
            JWK publicOnlyKey = rsaKey.toPublicJWK();
            assertNotNull(publicOnlyKey);
        }
    }

    @Test
    public void testInitKeys_HandlesMalformedStoredKey() {
        // Given: Malformed JSON in preferences
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(true);
        when(mockPreferences.getJwk(TEST_ALGORITHM)).thenReturn("{invalid json}");

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: Should regenerate key
        verify(mockPreferences, times(1)).setJwk(eq(TEST_ALGORITHM), any());
    }

    @Test
    public void testInitKeys_SupportsAllRSAAlgorithms() {
        // Given: All supported RSA algorithms
        Set<String> algorithms = new HashSet<>();
        algorithms.add("RSA1_5");
        algorithms.add("RSA-OAEP");
        algorithms.add("RSA-OAEP-256");
        algorithms.add("RSA-OAEP-384");
        algorithms.add("RSA-OAEP-512");

        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(any())).thenReturn(false);

        // When: Service is initialized
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: All algorithms should have keys generated
        verify(mockPreferences, times(5)).setJwk(any(), any());
    }

    @Test
    public void testInitKeys_NonPrimaryNodeWaitsForPrimary() throws Exception {
        // Given: Non-primary node and no existing keys
        when(mockXnatAppInfo.isPrimaryNode()).thenReturn(false);
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);

        // Generate a valid RSA key that will appear in database
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        RSAKey testKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .algorithm(JWEAlgorithm.RSA_OAEP_256)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                .keyIDFromThumbprint()
                .build();
        String keyJson = testKey.toJSONString();

        // Simulate primary node writing key after a delay
        when(mockPreferences.hasJwk(TEST_ALGORITHM))
                .thenReturn(false)  // First check: no key
                .thenReturn(false)  // Second check: still no key
                .thenReturn(true);  // Third check: key is now available
        when(mockPreferences.getJwk(TEST_ALGORITHM)).thenReturn(keyJson);

        // When: Service is initialized on non-primary node
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: Should have loaded key from database, not generated it
        verify(mockPreferences, never()).setJwk(any(), any());
        verify(mockPreferences, atLeast(3)).hasJwk(TEST_ALGORITHM);
        verify(mockPreferences, times(1)).getJwk(TEST_ALGORITHM);
    }

    @Test
    public void testInitKeys_PrimaryNodeGeneratesNonPrimaryWaits() throws Exception {
        // Given: Primary node scenario
        Set<String> algorithms = Collections.singleton(TEST_ALGORITHM);
        when(mockPlugin.getAllConfiguredIdTokenEncryptionAlgorithms()).thenReturn(algorithms);
        when(mockPreferences.hasJwk(TEST_ALGORITHM)).thenReturn(false);
        when(mockXnatAppInfo.isPrimaryNode()).thenReturn(true);

        // When: Primary node initializes
        keystoreService = new KeystoreServiceImpl(mockPlugin, mockPreferences, mockXnatAppInfo);

        // Then: Primary node should generate and persist
        verify(mockPreferences, times(1)).setJwk(eq(TEST_ALGORITHM), any());
        verify(mockXnatAppInfo, atLeastOnce()).isPrimaryNode();
    }
}
