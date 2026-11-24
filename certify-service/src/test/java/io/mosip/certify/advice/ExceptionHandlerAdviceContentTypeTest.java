package io.mosip.certify.advice;

import io.mosip.certify.core.exception.CertifyException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.StaticMessageSource;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

public class ExceptionHandlerAdviceContentTypeTest {

    private static final String[] ACCEPT_HEADERS = {
            "*/*", "application/xml", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    };

    private MockMvc mockMvc;

    @Before
    public void setup() {
        ExceptionHandlerAdvice advice = new ExceptionHandlerAdvice();
        ReflectionTestUtils.setField(advice, "messageSource", new StaticMessageSource());
        // XML converter is deliberately first to reproduce a bad negotiation order without needing an XML library.
        mockMvc = MockMvcBuilders.standaloneSetup(new FailingController())
                .setControllerAdvice(advice)
                .setMessageConverters(new StubXmlConverter(),
                        new MappingJackson2HttpMessageConverter())
                .build();
    }

    @Test
    public void certifyException_isJsonForAnyAcceptHeader() throws Exception {
        for (String accept : ACCEPT_HEADERS) {
            mockMvc.perform(get("/fail").header("Accept", accept))
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }

    @Test
    public void runtimeException_isJsonForAnyAcceptHeader() throws Exception {
        for (String accept : ACCEPT_HEADERS) {
            mockMvc.perform(get("/crash").header("Accept", accept))
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
        }
    }

    @Test
    public void methodNotAllowed_isJson() throws Exception {
        mockMvc.perform(post("/fail").header("Accept", "application/xml"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    static class StubXmlConverter extends AbstractHttpMessageConverter<Object> {
        StubXmlConverter() {
            super(MediaType.APPLICATION_XML);
        }

        @Override
        protected boolean supports(Class<?> clazz) {
            return true;
        }

        @Override
        protected Object readInternal(Class<?> clazz, HttpInputMessage input) {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void writeInternal(Object body, HttpOutputMessage output) throws java.io.IOException {
            output.getBody().write("<error/>".getBytes());
        }
    }

    @RestController
    static class FailingController {
        @GetMapping(value = "/fail", produces = "application/json")
        public String fail() {
            throw new CertifyException("test_error", "forced failure");
        }

        @GetMapping(value = "/crash", produces = "application/json")
        public String crash() {
            throw new IllegalStateException("boom");
        }
    }
}