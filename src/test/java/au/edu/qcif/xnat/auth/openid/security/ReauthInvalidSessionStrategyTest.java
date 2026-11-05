package au.edu.qcif.xnat.auth.openid.security;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class ReauthInvalidSessionStrategyTest {

    private final ReauthInvalidSessionStrategy strategy = new ReauthInvalidSessionStrategy();
    private final MockHttpServletResponse      response = new MockHttpServletResponse();

    private static MockHttpServletRequest get(final String uri) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.setRequestedSessionId("stale");
        request.setRequestedSessionIdValid(false);
        return request;
    }

    private static MockHttpServletRequest navigation(final String uri) {
        final MockHttpServletRequest request = get(uri);
        request.addHeader("Sec-Fetch-Mode", "navigate");
        request.addHeader("Sec-Fetch-Dest", "document");
        return request;
    }

    private static MockHttpServletRequest post(final String uri) {
        final MockHttpServletRequest request = navigation(uri);
        request.setMethod("POST");
        return request;
    }

    private void assertUnauthorizedOnly(final MockHttpServletRequest request) {
        assertEquals(401, response.getStatus());
        assertNull(response.getRedirectedUrl());
        // No new session: the browser's cookie may already belong to another window's fresh sign-in.
        assertNull(request.getSession(false));
    }

    @Test
    public void pageLoadGetsANewSessionAndReturnsToTheSameUrl() throws Exception {
        final MockHttpServletRequest request = navigation("/data/projects/P1");
        request.setQueryString("format=html&x=1");

        strategy.onInvalidSessionDetected(request, response);

        assertNotNull(request.getSession(false));
        assertEquals(303, response.getStatus());
        assertEquals("/data/projects/P1?format=html&x=1", response.getRedirectedUrl());
    }

    @Test
    public void redirectKeepsTheContextPath() throws Exception {
        final MockHttpServletRequest request = navigation("/xnat/app/template/Index.vm");
        request.setContextPath("/xnat");

        strategy.onInvalidSessionDetected(request, response);

        assertEquals("/xnat/app/template/Index.vm", response.getRedirectedUrl());
    }

    @Test
    public void xhrGetsUnauthorizedAndNoLogout() throws Exception {
        final MockHttpServletRequest request = get("/xapi/users");
        request.addHeader("Sec-Fetch-Mode", "cors");

        strategy.onInvalidSessionDetected(request, response);

        assertUnauthorizedOnly(request);
    }

    @Test
    public void apiClientGetsUnauthorized() throws Exception {
        final MockHttpServletRequest request = get("/data/projects");
        request.addHeader("Accept", "application/json");

        strategy.onInvalidSessionDetected(request, response);

        assertUnauthorizedOnly(request);
    }

    @Test
    public void framedPageLoadGetsUnauthorized() throws Exception {
        // The provider usually refuses to be framed, so sign-in can't complete inside an iframe.
        final MockHttpServletRequest request = get("/app/template/Page.vm");
        request.addHeader("Sec-Fetch-Mode", "navigate");
        request.addHeader("Sec-Fetch-Dest", "iframe");

        strategy.onInvalidSessionDetected(request, response);

        assertUnauthorizedOnly(request);
    }

    @Test
    public void formSubmissionReturnsToTheFormPage() throws Exception {
        // The submission can't be kept, since its CSRF token belonged to the old session.
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Referer", "https://xnat.example.org/app/action/DisplayItemAction/search_value/S1?popup=false");

        strategy.onInvalidSessionDetected(request, response);

        assertNotNull(request.getSession(false));
        assertEquals(303, response.getStatus());
        assertEquals("/app/action/DisplayItemAction/search_value/S1?popup=false", response.getRedirectedUrl());
    }

    @Test
    public void withoutFetchMetadataARefererOnThisHostCountsAsSameOrigin() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/action/ModifyItem");
        request.setServerName("xnat.example.org");
        request.addHeader("Accept", "text/html");
        // A proxy terminating TLS in front of XNAT makes the request http while the page was https.
        request.addHeader("Referer", "https://xnat.example.org/app/template/Edit.vm");

        strategy.onInvalidSessionDetected(request, response);

        assertEquals("/app/template/Edit.vm", response.getRedirectedUrl());
    }

    @Test
    public void formSubmissionWithoutRefererGoesToTheSiteRoot() throws Exception {
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "same-origin");

        strategy.onInvalidSessionDetected(request, response);

        assertNotNull(request.getSession(false));
        assertEquals("/", response.getRedirectedUrl());
    }

    @Test
    public void crossSiteFormSubmissionGoesToTheSiteRoot() throws Exception {
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "cross-site");
        request.addHeader("Referer", "https://elsewhere.example.org/form");

        strategy.onInvalidSessionDetected(request, response);

        assertEquals("/", response.getRedirectedUrl());
    }

    @Test
    public void refererOutsideTheContextPathGoesToTheSiteRoot() throws Exception {
        final MockHttpServletRequest request = post("/xnat/app/action/ModifyItem");
        request.setContextPath("/xnat");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Referer", "https://example.org/other-app/form");

        strategy.onInvalidSessionDetected(request, response);

        assertEquals("/xnat/", response.getRedirectedUrl());
    }

    @Test
    public void withoutFetchMetadataAnHtmlRequestIsAPageLoad() throws Exception {
        final MockHttpServletRequest request = get("/app/template/Index.vm");
        request.addHeader("Accept", "text/html,application/xhtml+xml");

        strategy.onInvalidSessionDetected(request, response);

        assertEquals("/app/template/Index.vm", response.getRedirectedUrl());
    }

    @Test
    public void withoutFetchMetadataAnXhrAskingForHtmlGetsUnauthorized() throws Exception {
        final MockHttpServletRequest request = get("/app/template/DataTypeSearch.vm");
        request.addHeader("Accept", "text/html, */*");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        strategy.onInvalidSessionDetected(request, response);

        assertUnauthorizedOnly(request);
    }
}
