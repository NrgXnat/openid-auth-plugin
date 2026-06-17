package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link BearerTokenExtractor}: pulling the raw JWT out of an
 * {@code Authorization: Bearer <jwt>} header. The scheme match is case-insensitive and the token is
 * trimmed; any other (or absent) header yields {@link Optional#empty()} so the filter can fall
 * through to other authentication mechanisms.
 */
public class BearerTokenExtractorTest {

    private final BearerTokenExtractor extractor = new BearerTokenExtractor();

    private static MockHttpServletRequest withAuthorization(final String value) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        if (value != null) {
            request.addHeader("Authorization", value);
        }
        return request;
    }

    @Test
    public void extractsTokenFromBearerHeader() {
        assertEquals(Optional.of("abc.def.ghi"), extractor.extract(withAuthorization("Bearer abc.def.ghi")));
    }

    @Test
    public void schemeMatchIsCaseInsensitive() {
        assertEquals(Optional.of("abc.def.ghi"), extractor.extract(withAuthorization("bearer abc.def.ghi")));
    }

    @Test
    public void trimsSurroundingWhitespaceFromToken() {
        assertEquals(Optional.of("abc.def.ghi"), extractor.extract(withAuthorization("Bearer    abc.def.ghi   ")));
    }

    @Test
    public void emptyWhenHeaderAbsent() {
        assertFalse(extractor.extract(withAuthorization(null)).isPresent());
    }

    @Test
    public void emptyWhenHeaderBlank() {
        assertFalse(extractor.extract(withAuthorization("")).isPresent());
    }

    @Test
    public void emptyForBasicScheme() {
        assertFalse(extractor.extract(withAuthorization("Basic dXNlcjpwYXNz")).isPresent());
    }

    @Test
    public void emptyWhenBearerTokenMissing() {
        // "Bearer" with no token (after trimming) is not a usable credential.
        assertFalse(extractor.extract(withAuthorization("Bearer    ")).isPresent());
    }

    @Test
    public void presentForLowercaseSchemeWithExtraSpacing() {
        assertTrue(extractor.extract(withAuthorization("bearer   token123")).isPresent());
    }
}
