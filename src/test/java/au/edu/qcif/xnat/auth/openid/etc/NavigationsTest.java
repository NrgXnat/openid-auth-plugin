package au.edu.qcif.xnat.auth.openid.etc;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NavigationsTest {

    private static MockHttpServletRequest navigate(final String dest) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/template/Login.vm");
        request.addHeader("Sec-Fetch-Mode", "navigate");
        request.addHeader("Sec-Fetch-Dest", dest);
        return request;
    }

    @Test
    public void frameNavigationIsAPageLoad() {
        assertTrue(Navigations.isNavigation(navigate("frame")));
    }

    @Test
    public void objectNavigationIsNotAPageLoad() {
        assertFalse(Navigations.isNavigation(navigate("object")));
    }

    @Test
    public void embedNavigationIsNotAPageLoad() {
        assertFalse(Navigations.isNavigation(navigate("embed")));
    }
}
