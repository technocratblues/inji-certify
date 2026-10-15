package io.mosip.certify.credential;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.credential.Credential;
import io.mosip.kernel.signature.dto.CWTSignRequestDto;
import io.mosip.kernel.signature.dto.CoseSignResponseDto;
import io.mosip.kernel.signature.dto.JWTSignatureResponseDto;
import io.mosip.kernel.signature.dto.JWSSignatureRequestDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import io.mosip.kernel.signature.service.SignatureService;
import io.mosip.certify.vcformatters.VCFormatter;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.Map;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CredentialTest {

    private VCFormatter mockFormatter;
    private SignatureService mockSignatureService;
    private CoseSignatureService mockCoseSignatureService;
    private Credential credential;

    @Before
    public void setUp() {
        mockFormatter = mock(VCFormatter.class);
        mockSignatureService = mock(SignatureService.class);
        mockCoseSignatureService = mock(CoseSignatureService.class);

        // Minimal subclass of Credential to allow testing
        credential = new Credential(mockFormatter, mockSignatureService) {
            @Override
            public boolean canHandle(String format) {
                return false;
            }
        };
        ReflectionTestUtils.setField(credential, "coseSignatureService", mockCoseSignatureService);
    }

    @Test
    public void testAddProofInBaseCredentialClass() {
        JWTSignatureResponseDto responseDto = new JWTSignatureResponseDto();
        responseDto.setJwtSignedData("signed.jwt.token");

        when(mockSignatureService.jwsSign(any(JWSSignatureRequestDto.class)))
                .thenReturn(responseDto);

        VCResult<?> result = credential.addProof(
                "unsignedVC",
                null,
                "RS256",
                "testAppId",
                "testRefId",
                "https://example.com/pubkey",
                "Ed25519Signature2020"
        );

        assertNotNull(result);
        assertEquals("vc", result.getFormat());
        assertEquals("signed.jwt.token", result.getCredential());
    }

    @Test
    public void testSignQRData_ReturnsSignedDataAndSendsCorrectRequest() {
        String payload = "payload-to-sign";
        String algorithm = "ES256";
        String appId = "app-1";
        String refId = "ref-1";
        String didUrl = "did:example:123";

        CoseSignResponseDto response = new CoseSignResponseDto();
        response.setSignedData("signed.cwt.data");

        when(mockCoseSignatureService.cwtSign(any(CWTSignRequestDto.class))).thenReturn(response);

        String result = credential.signQRData(payload, algorithm, appId, refId, didUrl);

        assertEquals("signed.cwt.data", result);

        ArgumentCaptor<CWTSignRequestDto> captor = ArgumentCaptor.forClass(CWTSignRequestDto.class);
        verify(mockCoseSignatureService, times(1)).cwtSign(captor.capture());
        CWTSignRequestDto sent = captor.getValue();

        assertNotNull(sent);
        assertEquals(payload, sent.getClaim169Payload());
        assertEquals(algorithm, sent.getAlgorithm());
        assertEquals(appId, sent.getApplicationId());
        assertEquals(refId, sent.getReferenceId());
        assertEquals(didUrl, sent.getIssuer());

        assertNotNull(sent.getProtectedHeader());
        assertTrue(Boolean.TRUE.equals(sent.getProtectedHeader().get("x5c")));
    }

    @Test(expected = RuntimeException.class)
    public void testSignQRData_ServiceThrowsRuntimeException_IsPropagated() {
        when(mockCoseSignatureService.cwtSign(any(CWTSignRequestDto.class)))
                .thenThrow(new RuntimeException("cwt service failure"));

        credential.signQRData("p", "alg", "app", "ref", "did");
    }

    // Runs signQRData and hands back the protected-header map sent to keymanager.
    // Each x5u/x5t test below only changes the two inputs.
    private Map<String, Object> signQrAndCaptureProtectedHeader(String x5uUrl, boolean x5tEnabled) {
        CoseSignResponseDto response = new CoseSignResponseDto();
        response.setSignedData("signed.cwt.data");
        when(mockCoseSignatureService.cwtSign(any(CWTSignRequestDto.class))).thenReturn(response);

        credential.signQRData("payload", "ES256", "app-1", "ref-1", "did:example:123", x5uUrl, x5tEnabled);

        ArgumentCaptor<CWTSignRequestDto> captor = ArgumentCaptor.forClass(CWTSignRequestDto.class);
        verify(mockCoseSignatureService, times(1)).cwtSign(captor.capture());
        return captor.getValue().getProtectedHeader();
    }

    @Test
    public void testSignQRData_X5tEnabled_RequestsCertHashAndDropsX5c() {
        Map<String, Object> header = signQrAndCaptureProtectedHeader(null, true);

        assertTrue(Boolean.TRUE.equals(header.get("includeCertificateHash")));
        assertFalse(header.containsKey("certificateUrl"));
        assertFalse(header.containsKey("x5c"));
    }

    @Test
    public void testSignQRData_X5uSet_AddsCertificateUrlAndDropsX5c() {
        String x5uUrl = "https://certify.example.com/v1/certify/.well-known/qr-signing-cert";

        Map<String, Object> header = signQrAndCaptureProtectedHeader(x5uUrl, false);

        assertEquals(x5uUrl, header.get("certificateUrl"));
        assertFalse(header.containsKey("includeCertificateHash"));
        assertFalse(header.containsKey("x5c"));
    }

    @Test
    public void testSignQRData_X5uAndX5tEnabled_AddsBothAndDropsX5c() {
        String x5uUrl = "https://certify.example.com/v1/certify/.well-known/qr-signing-cert";

        Map<String, Object> header = signQrAndCaptureProtectedHeader(x5uUrl, true);

        assertEquals(x5uUrl, header.get("certificateUrl"));
        assertTrue(Boolean.TRUE.equals(header.get("includeCertificateHash")));
        assertFalse(header.containsKey("x5c"));
    }

    @Test
    public void testSignQRData_BlankX5uAndX5tOff_FallsBackToX5c() {
        Map<String, Object> header = signQrAndCaptureProtectedHeader("   ", false);

        assertTrue(Boolean.TRUE.equals(header.get("x5c")));
        assertFalse(header.containsKey("certificateUrl"));
        assertFalse(header.containsKey("includeCertificateHash"));
    }

    @Test
    public void testSignQRData_KidIsRequestedInEveryHeaderCombination() {
        assertTrue(Boolean.TRUE.equals(signQrAndCaptureProtectedHeader(null, false).get("kid")));
        reset(mockCoseSignatureService);
        assertTrue(Boolean.TRUE.equals(signQrAndCaptureProtectedHeader(null, true).get("kid")));
        reset(mockCoseSignatureService);
        assertTrue(Boolean.TRUE.equals(signQrAndCaptureProtectedHeader("https://example.com/cert", true).get("kid")));
    }

}