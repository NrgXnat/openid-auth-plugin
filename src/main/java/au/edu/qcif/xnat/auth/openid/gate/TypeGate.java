package au.edu.qcif.xnat.auth.openid.gate;

import org.apache.commons.lang3.StringUtils;

import java.util.Set;

/**
 * Passes when the token's {@code typ} is one of the configured expected types (a case-sensitive
 * any-of membership test). Its purpose is to distinguish token kinds — e.g. an access token from an
 * id token — so a token of the wrong kind cannot be replayed against a path that expects the other.
 *
 * <p>{@code typ} is read from the token <strong>body</strong> claim first, falling back to the JWT
 * <strong>header</strong> when the body has none. This accommodates providers that place it in
 * either location: Keycloak emits a body claim ({@code "typ":"Bearer"}/{@code "ID"}), whereas
 * RFC 9068 / Duende IdentityServer put it in the header ({@code "typ":"at+jwt"} for access tokens,
 * {@code "JWT"} for id tokens). A token with no {@code typ} in either place is rejected.</p>
 */
final class TypeGate implements ClaimGate {

    private final Set<String> expectedTypes;

    TypeGate(final Set<String> expectedTypes) {
        this.expectedTypes = expectedTypes;
    }

    @Override
    public void check(final TokenContext token) throws ClaimGateException {
        final Object bodyTyp = token.claims().getClaim("typ");
        String typ = bodyTyp != null ? bodyTyp.toString() : null;
        if (StringUtils.isBlank(typ)) {
            final Object headerTyp = token.headers().get("typ");
            typ = headerTyp != null ? headerTyp.toString() : null;
        }
        if (typ == null || !expectedTypes.contains(typ)) {
            throw new ClaimGateException(
                    "Token typ '" + typ + "' is not one of the accepted types " + expectedTypes);
        }
    }
}
