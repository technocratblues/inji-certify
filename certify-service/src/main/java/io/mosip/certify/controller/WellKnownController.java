package io.mosip.certify.controller;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
public class WellKnownController {

    // The four media types RFC 9360 allows an x5u URI to return.
    private static final String PKIX_CERT = "application/pkix-cert";
    private static final String PKCS7_CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only";
    private static final String COSE_X509 = "application/cose-x509";
    private static final String COSE_X509_CHAIN = "application/cose-x509; usage=chain";

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    private JwksService jwksService;

    @Autowired
    private KeymanagerService keymanagerService;

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata() {
        return credentialConfigurationService.fetchCredentialIssuerMetadata();
    }

    @GetMapping(value = "/.well-known/did.json", produces = "application/json")
    public Map<String, Object> getDIDDocument() {
        return vcIssuanceService.getDIDDocument();
    }

    // x5u must resolve to an RFC 9360 media type. Defaults to pkix-cert (DER) and
    // switches on the Accept header, so verifiers can exercise every allowed format.
    @GetMapping(Constants.QR_SIGNING_CERT_PATH)
    public ResponseEntity<byte[]> getQrSigningCert(@RequestParam(Constants.APPLICATION_ID) String applicationId,
                                                   @RequestParam(value = Constants.REFERENCE_ID, required = false) String referenceId,
                                                   @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String accept) throws CertificateException {
        String mediaType = pickMediaType(accept);
        if (mediaType == null) {
            return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).build();
        }
        KeyPairGenerateResponseDto keyPair = keymanagerService.getCertificate(applicationId, Optional.ofNullable(referenceId));
        byte[] der = pemToDer(keyPair.getCertificate());
        byte[] body = switch (mediaType) {
            case PKCS7_CERTS_ONLY -> toPkcs7CertsOnly(der);
            case COSE_X509, COSE_X509_CHAIN -> toCborByteString(der);
            default -> der;
        };
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(mediaType)).body(body);
    }

    private static String pickMediaType(String accept) {
        if (accept == null || accept.isBlank()) {
            return PKIX_CERT;
        }
        String a = accept.toLowerCase().replaceAll("[\\s\"]", "");
        if (a.contains("*/*") || a.contains("application/*") || a.contains(PKIX_CERT)) {
            return PKIX_CERT;
        }
        if (a.contains("application/pkcs7-mime")) {
            return PKCS7_CERTS_ONLY;
        }
        if (a.contains(COSE_X509)) {
            return a.contains("usage=chain") ? COSE_X509_CHAIN : COSE_X509;
        }
        return null;
    }

    private static byte[] pemToDer(String pem) {
        String base64 = pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    // The JDK encodes a CertPath as a degenerate PKCS#7 SignedData, i.e. certs-only.
    private static byte[] toPkcs7CertsOnly(byte[] der) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(der));
        return factory.generateCertPath(List.of(cert)).getEncoded("PKCS7");
    }

    // cose-x509 is a CBOR sequence of byte strings (RFC 8949 major type 2), one per cert.
    private static byte[] toCborByteString(byte[] der) {
        int len = der.length;
        byte[] head;
        if (len < 24) {
            head = new byte[]{(byte) (0x40 | len)};
        } else if (len < 0x100) {
            head = new byte[]{0x58, (byte) len};
        } else if (len < 0x10000) {
            head = new byte[]{0x59, (byte) (len >> 8), (byte) len};
        } else {
            head = new byte[]{0x5A, (byte) (len >> 24), (byte) (len >> 16), (byte) (len >> 8), (byte) len};
        }
        byte[] out = new byte[head.length + len];
        System.arraycopy(head, 0, out, 0, head.length);
        System.arraycopy(der, 0, out, head.length, len);
        return out;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        try {
            Map<String, Object> response = jwksService.getJwks();

            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }

        } catch (Exception e) {
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }
}