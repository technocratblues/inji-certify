package io.mosip.certify.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonAccessDeniedHandlerTest {

    private final JsonAccessDeniedHandler handler = new JsonAccessDeniedHandler(new ObjectMapper());

    @Test
    void returnsJsonForAnyAcceptHeader() throws Exception {
        for (String accept : new String[]{"application/xml", "text/html,application/xml;q=0.9", "*/*"}) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/issuance/credential");
            request.addHeader("Accept", accept);
            MockHttpServletResponse response = new MockHttpServletResponse();

            handler.handle(request, response, new AccessDeniedException("denied"));

            assertEquals(403, response.getStatus());
            assertTrue(MediaType.APPLICATION_JSON.isCompatibleWith(
                    MediaType.parseMediaType(response.getContentType())));
            assertTrue(response.getContentAsString().contains("access_denied"));
        }
    }
}