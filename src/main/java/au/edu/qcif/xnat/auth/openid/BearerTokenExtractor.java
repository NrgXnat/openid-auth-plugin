package au.edu.qcif.xnat.auth.openid;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Pulls the raw JWT out of an {@code Authorization: Bearer <jwt>} request header.
 *
 * <p>The {@code Bearer} scheme is matched case-insensitively (per RFC 6750/7235 the scheme is
 * case-insensitive) and the token is trimmed. Any other scheme, a missing/blank header, or a
 * {@code Bearer} header with no token returns {@link Optional#empty()} so the bearer filter can
 * leave the request untouched and let other authentication mechanisms handle it.</p>
 */
final class BearerTokenExtractor {

    private static final String BEARER_PREFIX = "bearer ";

    Optional<String> extract(final HttpServletRequest request) {
        final String header = request.getHeader("Authorization");
        if (StringUtils.isBlank(header) || !StringUtils.startsWithIgnoreCase(header, BEARER_PREFIX)) {
            return Optional.empty();
        }
        final String token = header.substring(BEARER_PREFIX.length()).trim();
        return StringUtils.isBlank(token) ? Optional.empty() : Optional.of(token);
    }
}
