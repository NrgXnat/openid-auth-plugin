package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Passes when one of the configured accepted audiences is present in the token's {@code aud} list
 * (a membership test). Its purpose is to stop XNAT from honoring a token never minted for it
 * (confused-deputy / replay). A token with no audience, or whose audiences are disjoint from the
 * accepted set, is rejected.
 */
final class AudienceGate implements ClaimGate {

    private final Set<String> acceptedAudiences;

    AudienceGate(final Set<String> acceptedAudiences) {
        this.acceptedAudiences = acceptedAudiences;
    }

    @Override
    public void check(final JWTClaimsSet claims) throws ClaimGateException {
        final List<String> aud = claims.getAudience();
        if (aud == null || Collections.disjoint(aud, acceptedAudiences)) {
            throw new ClaimGateException(
                    "Token audience " + aud + " does not contain any accepted audience " + acceptedAudiences);
        }
    }
}
