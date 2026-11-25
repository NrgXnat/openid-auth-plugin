package au.edu.qcif.xnat.auth.openid.discovery;

import com.nimbusds.jose.util.JSONObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static au.edu.qcif.xnat.auth.openid.discovery.ProtectedResourceMetadata.WELL_KNOWN_PATH;

/**
 * Answers {@code GET} and {@code HEAD} for the RFC 9728 well-known document, and passes every other
 * request on. It sits right after XNAT's security headers are written and ahead of authentication and
 * session handling, so it answers anonymous callers without a login redirect and without creating a
 * session.
 */
@Component
public class ProtectedResourceMetadataFilter extends OncePerRequestFilter {

    static final String CACHE_CONTROL = "public, max-age=300";

    private final ProtectedResourceMetadata _metadata;

    public ProtectedResourceMetadataFilter(final ProtectedResourceMetadata metadata) {
        _metadata = metadata;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        final Optional<String> resource = isGetOrHead(request)
                ? wellKnownSuffix(request).flatMap(suffix -> _metadata.resourceFor(request, suffix))
                : Optional.empty();
        if (resource.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        final byte[] body = JSONObjectUtils.toJSONString(_metadata.document(resource.get())).getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Cache-Control", CACHE_CONTROL);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setContentLength(body.length);
        if (!"HEAD".equals(request.getMethod())) {
            response.getOutputStream().write(body);
        }
    }

    private static boolean isGetOrHead(final HttpServletRequest request) {
        return "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
    }

    /** The path after the well-known prefix (empty for the prefix itself), or empty if this is another URL. */
    static Optional<String> wellKnownSuffix(final HttpServletRequest request) {
        final String path = StringUtils.removeStart(request.getRequestURI(), request.getContextPath());
        if (WELL_KNOWN_PATH.equals(path)) {
            return Optional.of("");
        }
        return path.startsWith(WELL_KNOWN_PATH + "/") ? Optional.of(path.substring(WELL_KNOWN_PATH.length())) : Optional.empty();
    }
}
