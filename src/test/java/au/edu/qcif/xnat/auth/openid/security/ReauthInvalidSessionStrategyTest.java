package au.edu.qcif.xnat.auth.openid.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.session.InvalidSessionStrategy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@RunWith(MockitoJUnitRunner.class)
public class ReauthInvalidSessionStrategyTest {

    @Mock private InvalidSessionStrategy fallback;

    private final MockHttpServletResponse response = new MockHttpServletResponse();

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

    @Test
    public void pageLoadGetsANewSessionAndReturnsToTheSameUrl() throws Exception {
        final MockHttpServletRequest request = navigation("/data/projects/P1");
        request.setQueryString("format=html&x=1");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        assertNotNull(request.getSession(false));
        assertEquals("/data/projects/P1?format=html&x=1", response.getRedirectedUrl());
        verifyNoInteractions(fallback);
    }

    @Test
    public void redirectKeepsTheContextPath() throws Exception {
        final MockHttpServletRequest request = navigation("/xnat/app/template/Index.vm");
        request.setContextPath("/xnat");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        assertEquals("/xnat/app/template/Index.vm", response.getRedirectedUrl());
    }

    @Test
    public void xhrGoesToFallback() throws Exception {
        final MockHttpServletRequest request = get("/xapi/users");
        request.addHeader("Sec-Fetch-Mode", "cors");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
        assertNull(request.getSession(false));
    }

    @Test
    public void framedPageLoadGoesToFallback() throws Exception {
        // The provider usually refuses to be framed, so sign-in can't complete inside an iframe.
        final MockHttpServletRequest request = get("/app/template/Page.vm");
        request.addHeader("Sec-Fetch-Mode", "navigate");
        request.addHeader("Sec-Fetch-Dest", "iframe");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
    }

    @Test
    public void formSubmissionReturnsToTheFormPage() throws Exception {
        // The submission can't be kept, since its CSRF token belonged to the old session.
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Referer", "https://xnat.example.org/app/action/DisplayItemAction/search_value/S1?popup=false");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        assertNotNull(request.getSession(false));
        assertEquals(303, response.getStatus());
        assertEquals("/app/action/DisplayItemAction/search_value/S1?popup=false", response.getRedirectedUrl());
        verifyNoInteractions(fallback);
    }

    @Test
    public void withoutFetchMetadataARefererOnThisHostCountsAsSameOrigin() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/action/ModifyItem");
        request.setServerName("xnat.example.org");
        request.addHeader("Accept", "text/html");
        // A proxy terminating TLS in front of XNAT makes the request http while the page was https.
        request.addHeader("Referer", "https://xnat.example.org/app/template/Edit.vm");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        assertEquals("/app/template/Edit.vm", response.getRedirectedUrl());
    }

    @Test
    public void formSubmissionWithoutRefererGoesToFallback() throws Exception {
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "same-origin");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
        assertNull(request.getSession(false));
    }

    @Test
    public void crossSiteFormSubmissionGoesToFallback() throws Exception {
        final MockHttpServletRequest request = post("/app/action/ModifyItem");
        request.addHeader("Sec-Fetch-Site", "cross-site");
        request.addHeader("Referer", "https://elsewhere.example.org/form");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
    }

    @Test
    public void refererOutsideTheContextPathGoesToFallback() throws Exception {
        final MockHttpServletRequest request = post("/xnat/app/action/ModifyItem");
        request.setContextPath("/xnat");
        request.addHeader("Sec-Fetch-Site", "same-origin");
        request.addHeader("Referer", "https://example.org/other-app/form");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
    }

    @Test
    public void otherMethodsGoToFallback() throws Exception {
        final MockHttpServletRequest request = navigation("/app/action/ModifyItem");
        request.setMethod("PUT");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
    }

    @Test
    public void withoutFetchMetadataAnHtmlRequestIsAPageLoad() throws Exception {
        final MockHttpServletRequest request = get("/app/template/Index.vm");
        request.addHeader("Accept", "text/html,application/xhtml+xml");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        assertEquals("/app/template/Index.vm", response.getRedirectedUrl());
    }

    @Test
    public void withoutFetchMetadataAnXhrAskingForHtmlGoesToFallback() throws Exception {
        final MockHttpServletRequest request = get("/app/template/DataTypeSearch.vm");
        request.addHeader("Accept", "text/html, */*");
        request.addHeader("X-Requested-With", "XMLHttpRequest");

        new ReauthInvalidSessionStrategy(fallback).onInvalidSessionDetected(request, response);

        verify(fallback).onInvalidSessionDetected(request, response);
    }
}
