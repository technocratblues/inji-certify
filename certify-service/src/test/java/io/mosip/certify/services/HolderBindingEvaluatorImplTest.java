/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class HolderBindingEvaluatorImplTest {

    private HolderBindingEvaluatorImpl evaluator;

    @Before
    public void setUp() {
        evaluator = new HolderBindingEvaluatorImpl();
    }

    @Test
    public void isHolderBindingRequired_bothAttributesPresentAndNonEmpty_returnsTrue() {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setId("test-config");
        config.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        config.setProofTypesSupported(Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("RS256"))));

        assertTrue(evaluator.isHolderBindingRequired(config));
    }

    @Test
    public void isHolderBindingRequired_bothAttributesNull_returnsFalse() {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setId("test-config");
        config.setCryptographicBindingMethodsSupported(null);
        config.setProofTypesSupported(null);

        assertFalse(evaluator.isHolderBindingRequired(config));
    }

    @Test
    public void isHolderBindingRequired_bothAttributesEmpty_returnsFalse() {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setId("test-config");
        config.setCryptographicBindingMethodsSupported(Collections.emptyList());
        config.setProofTypesSupported(Collections.emptyMap());

        assertFalse(evaluator.isHolderBindingRequired(config));
    }

    @Test
    public void isHolderBindingRequired_onlyBindingMethodsPresent_returnsFalse() {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setId("test-config");
        config.setCryptographicBindingMethodsSupported(List.of("did:jwk"));
        config.setProofTypesSupported(null);

        assertFalse(evaluator.isHolderBindingRequired(config));
    }

    @Test
    public void isHolderBindingRequired_onlyProofTypesPresent_returnsFalse() {
        CredentialConfigurationSupported config = new CredentialConfigurationSupported();
        config.setId("test-config");
        config.setCryptographicBindingMethodsSupported(null);
        config.setProofTypesSupported(Map.of("jwt", Map.of()));

        assertFalse(evaluator.isHolderBindingRequired(config));
    }

    @Test
    public void isHolderBindingRequired_nullCredentialConfiguration_returnsFalse() {
        assertFalse(evaluator.isHolderBindingRequired(null));
    }
}