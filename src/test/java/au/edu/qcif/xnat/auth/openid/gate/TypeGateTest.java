package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.fail;

/**
 * Unit tests for {@link TypeGate}: the case-sensitive any-of membership test over the token's
 * {@code typ}, read from the body claim first and falling back to the JWT header. A pass is silent;
 * a failure throws {@link ClaimGateException}.
 */
public class TypeGateTest {

    private static Set<String> expecting(final String... types) {
        return new HashSet<>(Arrays.asList(types));
    }

    private static TokenContext withBodyTyp(final String typ) {
        return TokenContext.of(new JWTClaimsSet.Builder().claim("typ", typ).build());
    }

    private static TokenContext withHeaderTyp(final String typ) {
        return new TokenContext(new JWTClaimsSet.Builder().subject("alice").build(),
                Collections.<String, Object>singletonMap("typ", typ));
    }

    private static TokenContext withBodyAndHeaderTyp(final String bodyTyp, final String headerTyp) {
        return new TokenContext(new JWTClaimsSet.Builder().claim("typ", bodyTyp).build(),
                Collections.<String, Object>singletonMap("typ", headerTyp));
    }

    private static TokenContext withNoTyp() {
        return TokenContext.of(new JWTClaimsSet.Builder().subject("alice").build());
    }

    private static void assertPasses(final TypeGate gate, final TokenContext token) {
        try {
            gate.check(token);
        } catch (ClaimGateException e) {
            fail("token did not pass: " + e.getMessage());
        }
    }

    private static void assertRejects(final TypeGate gate, final TokenContext token) {
        try {
            gate.check(token);
            fail("expected ClaimGateException");
        } catch (ClaimGateException expected) {
            // pass
        }
    }

    @Test
    public void passesWhenBodyTypMatches() {
        assertPasses(new TypeGate(expecting("ID")), withBodyTyp("ID"));
    }

    @Test
    public void rejectsWhenBodyTypDoesNotMatch() {
        assertRejects(new TypeGate(expecting("ID")), withBodyTyp("Bearer"));
    }

    @Test
    public void passesWhenAnyOfSeveralExpectedTypesMatches() {
        assertPasses(new TypeGate(expecting("Bearer", "at+jwt")), withHeaderTyp("at+jwt"));
    }

    @Test
    public void fallsBackToHeaderWhenBodyHasNoTyp() {
        assertPasses(new TypeGate(expecting("at+jwt")), withHeaderTyp("at+jwt"));
    }

    @Test
    public void bodyTypTakesPrecedenceOverHeader() {
        // Body says Bearer (accepted); header says JWT (not accepted). Body wins -> passes.
        assertPasses(new TypeGate(expecting("Bearer")), withBodyAndHeaderTyp("Bearer", "JWT"));
        // Body says JWT (not accepted); header says at+jwt (accepted). Body wins -> rejects.
        assertRejects(new TypeGate(expecting("at+jwt")), withBodyAndHeaderTyp("JWT", "at+jwt"));
    }

    @Test
    public void rejectsWhenTypAbsentEverywhere() {
        assertRejects(new TypeGate(expecting("ID")), withNoTyp());
    }

    @Test
    public void rejectsWhenExpectedTypesEmpty() {
        // Enabled gate with no expected types is fail-closed.
        assertRejects(new TypeGate(Collections.<String>emptySet()), withBodyTyp("ID"));
    }

    @Test
    public void matchIsCaseSensitive() {
        assertRejects(new TypeGate(expecting("id")), withBodyTyp("ID"));
    }
}
