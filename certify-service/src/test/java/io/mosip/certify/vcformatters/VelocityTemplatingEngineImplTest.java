package io.mosip.certify.vcformatters;

import java.util.*;


import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.constants.VCDMConstants;
import org.json.JSONObject;
import org.junit.Assert;

import static io.mosip.certify.core.constants.Constants.DELIMITER;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.core.spi.RenderingTemplateService;

import lombok.SneakyThrows;


@RunWith(MockitoJUnitRunner.class)
public class VelocityTemplatingEngineImplTest {
    @InjectMocks
    private VelocityTemplatingEngineImpl formatter;
    @Mock
    CredentialConfigRepository credentialConfigRepository;
    @Mock
    RenderingTemplateService renderingTemplateService;

    private CredentialConfig vc2;
    private CredentialConfig vc3;
    private CredentialConfig vc4;

    // Template Keys used in tests, derived from CredentialConfig objects
    private String vc2TemplateKey;

    private String vc3TemplateKey;

    private String vc4TemplateKey;


    private final String FACE_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII";


    @SneakyThrows
    @Before
    public void setUp() {

        // vc2 definition
        String vc2Type = "MockVerifiableCredential,VerifiableCredential";
        String vc2Context = "https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        String vc2Format = "ldp_vc";
        vc2TemplateKey = vc2Type + DELIMITER + vc2Context + DELIMITER + vc2Format;
        vc2 = initTemplate("""
                        {
                            "@context": ["https://www.w3.org/ns/credentials/v2"],
                            "id": "${_id}",
                            "issuer": "${_issuer}",
                            "type": ["VerifiableCredential", "MockVerifiableCredential"],
                            "validFrom": "${validFrom}",
                            "validUntil": "${validUntil}",
                            "credentialSubject": {
                                "gender": "${gender}",
                                "postalCode": ${postalCode},
                                "fullName": "${fullName}",
                                "dateOfBirth": "${dateOfBirth}",
                                "province": "${province}",
                                "phone": "${phone}",
                                "addressLine1": ${addressLine1},
                                "region": "${region}",
                                "vcVer": "${vcVer}",
                                "UIN": ${UIN},
                                "email": "${email}",
                                "face": "${face}"
                            }
                        }
                """,
                vc2Type, vc2Context, vc2Format, "did:example:issuer2", "appId2", "refId2", "EdDSA", "$.phone", "testCryptoSuite"
        );

        // vc3 definition - with quotes fixed for string template variables
        String vc3Type = "MockVerifiableCredential,VerifiableCredential";
        String vc3Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc3Format = "ldp_vc";
        vc3TemplateKey = vc3Type + DELIMITER + vc3Context + DELIMITER + vc3Format;
        vc3 = initTemplate("""
                        {
                            "@context": ["https://www.w3.org/2018/credentials/v1", "https://vharsh.github.io/DID/mock-context.json"],
                            "id": "${_id}",
                            "issuer": "${_issuer}",
                            "type": ["VerifiableCredential", "MockVerifiableCredential"],
                            "issuanceDate": "${validFrom}",
                            "expirationDate": "${validUntil}",
                            "credentialSubject": {
                                "gender": "${gender}",
                                "postalCode": ${postalCode},
                                "fullName": "${fullName}",
                                "dateOfBirth": "${dateOfBirth}",
                                "province": "${province}",
                                "phone": "${phone}",
                                "addressLine1": ${addressLine1},
                                "region": "${region}",
                                "vcVer": "${vcVer}",
                                "UIN": ${UIN},
                                "email": "${email}",
                                "face": "${face}"
                            }
                        }
                """,
                vc3Type, vc3Context, vc3Format, "did:example:issuer3", "appId3", "refId3", "EdDSA", null, "testCryptoSuite"
        );


        // vc4 definition (template string is null)
        String vc4Type = "TestVerifiableCredential,VerifiableCredential";
        String vc4Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
        String vc4Format = "ldp_vc";
        vc4TemplateKey = vc4Type + DELIMITER + vc4Context + DELIMITER + vc4Format;
        vc4 = initTemplate(null,
                vc4Type, vc4Context, vc4Format, "did:example:issuer4", "appId4", "refId4", "RSA", null, "testCryptoSuite"
        );


        ReflectionTestUtils.setField(formatter, "defaultExpiryDuration", "P730d");
        ReflectionTestUtils.setField(formatter, "idPrefix", "uurn:uuid:");


        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(vc2Format, vc2Type, vc2Context)).thenReturn(Optional.of(vc2));

        formatter.initialize(); // Initializes VelocityEngine
    }

    private CredentialConfig initTemplate(String template, String type, String context, String format, String didUrl, String keyManagerAppId, String keyManagerRefId, String signatureAlgo, String sdClaim, String signatureCryptoSuite) {
        CredentialConfig t = new CredentialConfig();
        if(template != null) {
            template = Base64.getEncoder().encodeToString(template.getBytes());
        }

        t.setVcTemplate(template);
        t.setCredentialType(type);
        t.setContext(context);
        t.setCredentialFormat(format); // Make sure CredentialConfig has this field and setter
        t.setDidUrl(didUrl);
        t.setKeyManagerAppId(keyManagerAppId);
        t.setKeyManagerRefId(keyManagerRefId);
        t.setSignatureAlgo(signatureAlgo);
        t.setSdClaim(sdClaim);
        t.setSignatureCryptoSuite(signatureCryptoSuite);
        return t;
    }

    @Ignore("This test requires a running local server and is for manual/integration testing")
    @Test
    public void testTemplating_localOnly() { /* ... unchanged ... */ }


    @Test
    public void testGetProofAlgorithm() {
        // Uses vc2 by default from setUp's findById mock
        String expected = vc2.getSignatureAlgo();
        Assert.assertEquals(expected, formatter.getProofAlgorithm(vc2TemplateKey));
    }

    @Test
    public void testGetDidUrl() {
        // Uses vc2 by default
        String expected = vc2.getDidUrl();
        Assert.assertEquals(expected, formatter.getDidUrl(vc2TemplateKey));
    }

    @Test
    public void testGetRefID() {
        // Uses vc2 by default
        String expected = vc2.getKeyManagerRefId();
        Assert.assertEquals(expected, formatter.getRefID(vc2TemplateKey));
    }

    @Test
    public void testGetAppID() {
        // Uses vc2 by default
        String expected = vc2.getKeyManagerAppId();
        Assert.assertEquals(expected, formatter.getAppID(vc2TemplateKey));
    }

    @Test
    public void testGetSelectiveDisclosureInfo() {
        // Uses vc2 by default
        List<String> expectedList = Arrays.asList(vc2.getSdClaim().split(","));
        Assert.assertEquals(expectedList, formatter.getSelectiveDisclosureInfo(vc2TemplateKey));
    }

    @Test
    public void testGetSignatureCryptoSuite() {
        // Uses vc2 by default
        String expected = vc2.getSignatureCryptoSuite();
        Assert.assertEquals(expected, formatter.getSignatureCryptoSuite(vc2TemplateKey));
    }

//    @Test
//    @SneakyThrows
//    public void testFormat_WithMapInput_HappyPath() {
//        // Mock for vc3
//        String vc3Type = "MockVerifiableCredential,VerifiableCredential";
//        String vc3Context = "https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1";
//        String vc3Format = "ldp_vc";
//        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(vc3Format, vc3Type, vc3Context)).thenReturn(Optional.of(vc3));
//
//        Map<String, Object> templateInput = new HashMap<>();
//        templateInput.put(Constants.TEMPLATE_NAME, vc3TemplateKey);
//        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
//        templateInput.put("vcVer", "VC-V3");
//        templateInput.put("fullName", "Test User Three"); // String, template vc3 now quotes it.
//        templateInput.put("UIN", 789012L);
//        templateInput.put("postalCode", 789);
//        templateInput.put("gender", "other"); // String, template vc3 quotes it.
//        templateInput.put("dateOfBirth", "03/03/1993");
//        templateInput.put("email", "vc3@example.com");
//        templateInput.put("phone", "3333333333");
//        templateInput.put("addressLine1", List.of("VC3 Addr", "Line 2"));
//        templateInput.put("province", "VC3 Province"); // String, template vc3 quotes it.
//        templateInput.put("region", "VC3 Region");   // String, template vc3 quotes it.
//        templateInput.put("face", "data:image/gif;base64,vc3facedata");
//        templateInput.put(VCDM2Constants.VALID_FROM, "2023-03-01T00:00:00Z"); // Explicitly provide
//        templateInput.put(VCDM2Constants.VALID_UNTIL, "2025-03-01T00:00:00Z"); // Explicitly provide
//        templateInput.put(VCDMConstants.CREDENTIAL_ID, "uurn:uuid:");
//
//
//        String result = formatter.format(templateInput, new HashMap<>()); // Uses the overloaded format(Map)
//        assertNotNull(result);
//
//        JSONObject actualJsonObj = new JSONObject(result);
//        assertTrue(actualJsonObj.has("id"));
//        assertTrue(actualJsonObj.getString("id").startsWith("uurn:uuid:"));
//        Assert.assertEquals("Test User Three", actualJsonObj.getJSONObject("credentialSubject").getString("fullName"));
//        Assert.assertEquals(789012L, actualJsonObj.getJSONObject("credentialSubject").getLong("UIN"));
//        Assert.assertEquals("https://example.com/fake-issuer", actualJsonObj.getString("issuer"));
//    }

    // ==================== Optional Holder Binding: generation-layer tests ====================
    // These verify VelocityTemplatingEngineImpl#format() only injects holder-binding fields
    // ("id" for LDP VC, "cnf" for SD-JWT) into the rendered credential when the caller
    // (CertifyIssuanceServiceImpl / VCIssuanceServiceImpl) actually populated them, which only
    // happens when a holderId was established via proof validation.

    private CredentialConfig minimalTemplate;
    private String minimalTemplateKey;

    private void registerMinimalTemplate() {
        String type = "MinimalVerifiableCredential,VerifiableCredential";
        String context = "https://www.w3.org/2018/credentials/v1";
        String format = "ldp_vc";
        minimalTemplateKey = type + DELIMITER + context + DELIMITER + format;
        minimalTemplate = initTemplate(
                "{\"@context\": [\"https://www.w3.org/2018/credentials/v1\"], \"type\": [\"VerifiableCredential\"]}",
                type, context, format, "did:example:issuer-minimal", "appIdMin", "refIdMin", "EdDSA", null, "testCryptoSuite"
        );
        when(credentialConfigRepository.findByCredentialFormatAndCredentialTypeAndContext(format, type, context))
                .thenReturn(Optional.of(minimalTemplate));
    }

    @Test
    @SneakyThrows
    public void testFormat_OmitsIdAndCnf_WhenHolderIdIsNull() {
        registerMinimalTemplate();

        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, minimalTemplateKey);
        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
        // No CREDENTIAL_ID, VCTYPE, CONFIRMATION or ISSUER supplied: mirrors what
        // CertifyIssuanceServiceImpl/VCIssuanceServiceImpl now pass when holderId is null.

        String result = formatter.format(templateInput);
        assertNotNull(result);

        JSONObject actualJsonObj = new JSONObject(result);
        assertTrue("id must not be present when CREDENTIAL_ID was not supplied", !actualJsonObj.has(VCDMConstants.ID));
        assertTrue("cnf must not be present when holder-binding params were not supplied", !actualJsonObj.has(Constants.CONFIRMATION));
    }

    @Test
    @SneakyThrows
    public void testFormat_IncludesId_WhenCredentialIdIsProvided() {
        registerMinimalTemplate();

        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, minimalTemplateKey);
        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
        templateInput.put(VCDMConstants.CREDENTIAL_ID, "uurn:uuid:test-credential-id");

        String result = formatter.format(templateInput);
        JSONObject actualJsonObj = new JSONObject(result);

        assertTrue("id must be present when CREDENTIAL_ID was supplied", actualJsonObj.has(VCDMConstants.ID));
        Assert.assertEquals("uurn:uuid:test-credential-id", actualJsonObj.getString(VCDMConstants.ID));
    }

    @Test
    @SneakyThrows
    public void testFormat_IncludesCnf_WhenHolderBindingParamsAreProvided() {
        registerMinimalTemplate();

        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, minimalTemplateKey);
        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
        templateInput.put(Constants.VCTYPE, "TestVct");
        templateInput.put(Constants.CONFIRMATION, Map.of("kid", "did:jwk:test-holder"));
        templateInput.put(Constants.ISSUER, "https://example.com/fake-issuer");

        String result = formatter.format(templateInput);
        JSONObject actualJsonObj = new JSONObject(result);

        assertTrue("cnf must be present when holder-binding params were supplied", actualJsonObj.has(Constants.CONFIRMATION));
        Assert.assertEquals("did:jwk:test-holder", actualJsonObj.getJSONObject(Constants.CONFIRMATION).getString("kid"));
    }

    @Test
    @SneakyThrows
    public void testFormat_OmitsCnf_WhenOnlyPartialHolderBindingParamsProvided() {
        registerMinimalTemplate();

        Map<String, Object> templateInput = new HashMap<>();
        templateInput.put(Constants.TEMPLATE_NAME, minimalTemplateKey);
        templateInput.put(Constants.DID_URL, "https://example.com/fake-issuer");
        // CONFIRMATION present but VCTYPE/ISSUER missing: format() requires all three together.
        templateInput.put(Constants.CONFIRMATION, Map.of("kid", "did:jwk:test-holder"));

        String result = formatter.format(templateInput);
        JSONObject actualJsonObj = new JSONObject(result);

        assertTrue("cnf must not be present unless VCTYPE, CONFIRMATION and ISSUER are all supplied together",
                !actualJsonObj.has(Constants.CONFIRMATION));
    }
}