package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.fail;

/**
 * Unit tests for {@link AudienceGate}: the membership test "is one of my accepted audiences present
 * in the token's aud list?". A pass is silent; a failure throws {@link ClaimGateException}.
 */
public class AudienceGateTest {

    private static Set<String> accepting(final String... audiences) {
        return new HashSet<>(Arrays.asList(audiences));
    }

    private static JWTClaimsSet withAudience(final String... aud) {
        return new JWTClaimsSet.Builder().audience(Arrays.asList(aud)).build();
    }

    private static void assertPasses(final AudienceGate gate, final JWTClaimsSet claims) {
        try {
            gate.check(TokenContext.of(claims));
        } catch (ClaimGateException e) {
            fail("claims did not pass");
        }
        // throws on failure; reaching here is the pass assertion
    }

    private static void assertRejects(final AudienceGate gate, final JWTClaimsSet claims) {
        try {
            gate.check(TokenContext.of(claims));
            fail("expected ClaimGateException");
        } catch (ClaimGateException expected) {
            // pass
        }
    }

    @Test
    public void passesWhenAudienceMatches() {
        assertPasses(new AudienceGate(accepting("xnat")), withAudience("xnat"));
    }

    @Test
    public void passesWhenOneOfSeveralAudiencesMatches() {
        assertPasses(new AudienceGate(accepting("xnat")), withAudience("jupyter", "xnat"));
    }

    @Test
    public void rejectsWhenAudienceDisjoint() {
        assertRejects(new AudienceGate(accepting("xnat")), withAudience("jupyter"));
    }

    @Test
    public void rejectsWhenAudienceAbsent() {
        assertRejects(new AudienceGate(accepting("xnat")), new JWTClaimsSet.Builder().subject("alice").build());
    }

    @Test
    public void rejectsWhenAudienceEmpty() {
        assertRejects(new AudienceGate(accepting("xnat")),
                new JWTClaimsSet.Builder().audience(Collections.<String>emptyList()).build());
    }
}
