package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.etc.MediaTypes;
import org.apache.commons.lang3.StringUtils;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Passes when the token's {@code typ} is one of the configured expected types (a case-sensitive
 * any-of membership test in which, as in RFC 7515, an {@code application/} prefix is optional on a
 * header {@code typ}). Its
 * purpose is to distinguish token kinds — e.g. an access token from an id token — so a token of the
 * wrong kind cannot be replayed against a path that expects the other.
 *
 * <p>{@code typ} is read from the token <strong>body</strong> claim first, falling back to the JWT
 * <strong>header</strong> when the body has none. This accommodates providers that place it in
 * either location: Keycloak emits a body claim ({@code "typ":"Bearer"}/{@code "ID"}), whereas
 * RFC 9068 / Duende IdentityServer put it in the header ({@code "typ":"at+jwt"} for access tokens,
 * {@code "JWT"} for id tokens). A token with no {@code typ} in either place is rejected.</p>
 */
final class TypeGate implements ClaimGate {

    private final Set<String> expectedTypes;
    private final Set<String> normalizedExpectedTypes;

    TypeGate(final Set<String> expectedTypes) {
        this.expectedTypes = new LinkedHashSet<>(expectedTypes);
        this.normalizedExpectedTypes = expectedTypes.stream().map(MediaTypes::withoutApplicationPrefix).collect(Collectors.toSet());
    }

    @Override
    public void check(final TokenContext token) throws ClaimGateException {
        final Object bodyTyp = token.claims().getClaim("typ");
        String typ = bodyTyp != null ? bodyTyp.toString() : null;
        boolean fromHeader = false;
        if (StringUtils.isBlank(typ)) {
            final Object headerTyp = token.headers().get("typ");
            typ = headerTyp != null ? headerTyp.toString() : null;
            fromHeader = true;
        }
        final boolean accepted = typ != null && (fromHeader
                ? normalizedExpectedTypes.contains(MediaTypes.withoutApplicationPrefix(typ))
                : expectedTypes.contains(typ) || normalizedExpectedTypes.contains(typ));
        if (!accepted) {
            throw new ClaimGateException(
                    "Token typ '" + typ + "' is not one of the accepted types " + expectedTypes);
        }
    }
}
