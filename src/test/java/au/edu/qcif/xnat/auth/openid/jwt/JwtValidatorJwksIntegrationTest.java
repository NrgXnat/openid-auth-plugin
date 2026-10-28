package au.edu.qcif.xnat.auth.openid.jwt;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Exercises {@link JwtValidator#remoteJwks} against a JWKS endpoint served by WireMock. */
public class JwtValidatorJwksIntegrationTest {

    private static final String ISSUER = "https://idp.example/realms/xnat";

    @Rule
    public final WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    private static RSAKey publishedKey;   // kid "k1" — served by the JWKS endpoint
    private static RSAKey unpublishedKey;  // kid "k99" — never in the JWKS

    @BeforeClass
    public static void generateKeys() throws Exception {
        publishedKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        unpublishedKey = new RSAKeyGenerator(2048).keyID("k99").generate();
    }

    private static ResponseDefinitionBuilder jwks() {
        return aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(publishedKey.toPublicJWK()).toString());
    }

    private String jwksUrl() {
        return "http://localhost:" + wireMock.port() + "/jwks";
    }

    private JwtValidator validator() throws Exception {
        return new JwtValidator(ISSUER, JwtValidator.remoteJwks(new URL(jwksUrl())));
    }

    private static String sign(final RSAKey key) throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build();
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    public void acceptsTokenSignedByPublishedKey() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).willReturn(jwks()));

        final JWTClaimsSet claims = validator().validate(sign(publishedKey));

        assertEquals("alice", claims.getSubject());
    }

    @Test
    public void rejectsTokenWithKidNotInJwks() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).willReturn(jwks()));
        final JwtValidator validator = validator();
        try {
            validator.validate(sign(unpublishedKey));
            fail("expected JwtValidationException");
        } catch (JwtValidationException expected) {
            // pass — no matching key in the JWKS
        }
    }

    @Test
    public void waitsForSlowJwksEndpoint() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).willReturn(jwks().withFixedDelay(1_500)));

        final JWTClaimsSet claims = validator().validate(sign(publishedKey));

        assertEquals("alice", claims.getSubject());
    }

    @Test
    public void retriesFailedJwksFetchAndLogsTheFailure() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).inScenario("flaky").whenScenarioStateIs(STARTED)
                .willReturn(aResponse().withStatus(503))
                .willSetStateTo("recovered"));
        stubFor(get(urlEqualTo("/jwks")).inScenario("flaky").whenScenarioStateIs("recovered")
                .willReturn(jwks()));
        final Logger logger = (Logger) LoggerFactory.getLogger(JwtValidator.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        final JWTClaimsSet claims;
        try {
            claims = validator().validate(sign(publishedKey));
        } finally {
            logger.detachAppender(appender);
        }

        assertEquals("alice", claims.getSubject());
        assertTrue(appender.list.stream().anyMatch(event ->
                event.getLevel() == Level.WARN && event.getFormattedMessage().contains(jwksUrl())));
    }
}
