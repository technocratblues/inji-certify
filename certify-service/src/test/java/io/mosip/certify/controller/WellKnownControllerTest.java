package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(WellKnownController.class)
class WellKnownControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialConfigurationService credentialConfigurationService;

    @MockBean
    private VCIssuanceService vcIssuanceService;

    @MockBean
    private ParsedAccessToken parsedAccessToken;

    // AccessTokenValidationFilter is a @Component, so the web slice builds it
    // and every collaborator it autowires has to exist here too.
    @MockBean
    private io.mosip.certify.dpop.DpopProofValidator dpopProofValidator;

    @MockBean
    private JwksService jwksService;

    @MockBean
    private KeymanagerService keymanagerService;

    @InjectMocks
    private WellKnownController wellKnownController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getCredentialIssuerMetadata() throws Exception {
        CredentialIssuerMetadataDTO mockMetadata = mock(CredentialIssuerMetadataDTO.class);
        when(credentialConfigurationService.fetchCredentialIssuerMetadata()).thenReturn(mockMetadata);
        mockMvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk());
        verify(credentialConfigurationService, times(1)).fetchCredentialIssuerMetadata();
    }

    @Test
    void getDIDDocument_success() throws Exception {
        Map<String, Object> mockDidDoc = Collections.singletonMap("id", "did:example:123");
        when(vcIssuanceService.getDIDDocument()).thenReturn(mockDidDoc);
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("did:example:123"));
    }

    @Test
    void getDIDDocument_notFound_returnsEmpty() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenReturn(null);
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    void getDIDDocument_serviceThrowsException_returnsError() throws Exception {
        when(vcIssuanceService.getDIDDocument()).thenThrow(new InvalidRequestException("unsupported_in_current_plugin_mode"));
        mockMvc.perform(get("/.well-known/did.json"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.errors[0].errorCode").value("unsupported_in_current_plugin_mode"));
    }

    @Test
    void getJwks_success_returnsJwkSet() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", Collections.singletonList(
                        Map.of(
                                "kty", "RSA",
                                "kid", "test-key-id",
                                "use", "sig",
                                "n", "test-modulus",
                                "e", "AQAB"
                        )
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-key-id"));

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_emptyKeysList_returnsOkWithEmptyKeys() throws Exception {
        Map<String, Object> emptyJwks = Map.of("keys", Collections.emptyList());
        when(jwksService.getJwks()).thenReturn(emptyJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_nullResponse_returnsServiceUnavailable() throws Exception {
        when(jwksService.getJwks()).thenReturn(null);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_missingKeysField_returnsServiceUnavailable() throws Exception {
        Map<String, Object> invalidResponse = Collections.singletonMap("invalid", "response");
        when(jwksService.getJwks()).thenReturn(invalidResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_serviceThrowsException_returnsServiceUnavailable() throws Exception {
        when(jwksService.getJwks()).thenThrow(new RuntimeException("Keymanager service unavailable"));

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_nullKeysList_returnsOkWithEmptyKeys() throws Exception {
        Map<String, Object> nullKeysResponse = Collections.singletonMap("keys", null);
        when(jwksService.getJwks()).thenReturn(nullKeysResponse);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").doesNotExist());

        verify(jwksService, times(1)).getJwks();
    }

    @Test
    void getJwks_multipleKeys_returnsAllKeys() throws Exception {
        Map<String, Object> mockJwks = Map.of(
                "keys", List.of(
                        Map.of("kty", "RSA", "kid", "key1", "use", "sig"),
                        Map.of("kty", "EC", "kid", "key2", "use", "sig")
                )
        );
        when(jwksService.getJwks()).thenReturn(mockJwks);

        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(2))
                .andExpect(jsonPath("$.keys[0].kid").value("key1"))
                .andExpect(jsonPath("$.keys[1].kid").value("key2"));

        verify(jwksService, times(1)).getJwks();
    }

    private static final String TEST_CERT_PEM =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIBijCCAS+gAwIBAgIUDACL0BUp7yAnNmAgHHQ8iQhBjhEwCgYIKoZIzj0EAwIw\n" +
                    "GTEXMBUGA1UEAwwOVGVzdCBRUiBTaWduZXIwIBcNMjYxMTI4MDYyNDU3WhgPMjEy\n" +
                    "NjExMDQwNjI0NTdaMBkxFzAVBgNVBAMMDlRlc3QgUVIgU2lnbmVyMFkwEwYHKoZI\n" +
                    "zj0CAQYIKoZIzj0DAQcDQgAEGKu30CDi+Pqjk90x4loBQvmgZcSj6Lclo7Nz/3Dg\n" +
                    "VUkYl0NzdYm+G0qWSuJfLmpr3ym+DduzdJCvNOJqRVCz2KNTMFEwHQYDVR0OBBYE\n" +
                    "FKC13XgGJgKCO9nocrPdRFrTMAHBMB8GA1UdIwQYMBaAFKC13XgGJgKCO9nocrPd\n" +
                    "RFrTMAHBMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKEysDhE\n" +
                    "Zwpv3jABR8R7SJI1sbMUruhtXG9DGPReRKwYAiEAs5PRqQ/pr9HFMK7/GfY8Cor1\n" +
                    "fQZvw7e9IchqLTlLubA=\n" +
                    "-----END CERTIFICATE-----";

    private byte[] testCertDer() throws Exception {
        return CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(TEST_CERT_PEM.getBytes())).getEncoded();
    }

    private void stubQrSigningCert(String appId, Optional<String> refId) {
        KeyPairGenerateResponseDto keyPair = mock(KeyPairGenerateResponseDto.class);
        when(keyPair.getCertificate()).thenReturn(TEST_CERT_PEM);
        when(keymanagerService.getCertificate(appId, refId)).thenReturn(keyPair);
    }

    @Test
    void getQrSigningCert_withReferenceId_returnsDerPkixCert() throws Exception {
        stubQrSigningCert("CERTIFY_VC_SIGN_ED25519", Optional.of("ED25519_SIGN"));

        mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "CERTIFY_VC_SIGN_ED25519")
                        .param("referenceId", "ED25519_SIGN"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/pkix-cert"))
                .andExpect(content().bytes(testCertDer()));

        verify(keymanagerService, times(1)).getCertificate("CERTIFY_VC_SIGN_ED25519", Optional.of("ED25519_SIGN"));
    }

    @Test
    void getQrSigningCert_withoutReferenceId_passesEmptyOptional() throws Exception {
        stubQrSigningCert("CERTIFY_VC_SIGN_ED25519", Optional.empty());

        mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "CERTIFY_VC_SIGN_ED25519"))
                .andExpect(status().isOk())
                .andExpect(content().bytes(testCertDer()));

        verify(keymanagerService, times(1)).getCertificate("CERTIFY_VC_SIGN_ED25519", Optional.empty());
    }

    @Test
    void getQrSigningCert_acceptPkcs7_returnsCertsOnlyBundle() throws Exception {
        stubQrSigningCert("APP", Optional.empty());

        byte[] body = mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "APP")
                        .header("Accept", "application/pkcs7-mime; smime-type=\"certs-only\""))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/pkcs7-mime; smime-type=certs-only"))
                .andReturn().getResponse().getContentAsByteArray();

        List<? extends Certificate> certs = List.copyOf(CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(body)));
        org.junit.jupiter.api.Assertions.assertEquals(1, certs.size());
        org.junit.jupiter.api.Assertions.assertArrayEquals(testCertDer(), certs.get(0).getEncoded());
    }

    @Test
    void getQrSigningCert_acceptCoseX509_returnsCborByteString() throws Exception {
        stubQrSigningCert("APP", Optional.empty());
        byte[] der = testCertDer();

        byte[] body = mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "APP")
                        .header("Accept", "application/cose-x509"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/cose-x509"))
                .andReturn().getResponse().getContentAsByteArray();

        assertCborByteString(body, der);
    }

    @Test
    void getQrSigningCert_acceptCoseX509Chain_setsUsageParam() throws Exception {
        stubQrSigningCert("APP", Optional.empty());
        byte[] der = testCertDer();

        byte[] body = mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "APP")
                        .header("Accept", "application/cose-x509; usage=chain"))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/cose-x509; usage=chain"))
                .andReturn().getResponse().getContentAsByteArray();

        assertCborByteString(body, der);
    }

    @Test
    void getQrSigningCert_unsupportedAccept_returns406() throws Exception {
        mockMvc.perform(get("/.well-known/qr-signing-cert")
                        .param("applicationId", "APP")
                        .header("Accept", "application/x-pem-file"))
                .andExpect(status().isNotAcceptable());

        verifyNoInteractions(keymanagerService);
    }

    // Major type 2 header (0x40-0x5B), then the DER bytes exactly once.
    private void assertCborByteString(byte[] body, byte[] der) {
        org.junit.jupiter.api.Assertions.assertEquals(2, (body[0] & 0xFF) >> 5);
        org.junit.jupiter.api.Assertions.assertArrayEquals(der, Arrays.copyOfRange(body, body.length - der.length, body.length));
        org.junit.jupiter.api.Assertions.assertTrue(body.length - der.length <= 5);
    }
}