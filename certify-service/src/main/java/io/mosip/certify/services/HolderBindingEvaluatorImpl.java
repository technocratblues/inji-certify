/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Objects;


@Slf4j
@Component
public class HolderBindingEvaluatorImpl implements HolderBindingEvaluator {

    @Override
    public boolean isHolderBindingRequired(CredentialConfigurationSupported credentialConfigurationSupported) {
        if (Objects.isNull(credentialConfigurationSupported)) {
            log.debug("No credential configuration provided; treating holder binding as not required.");
            return false;
        }

        boolean hasBindingMethods = isPresent(credentialConfigurationSupported.getCryptographicBindingMethodsSupported());
        boolean hasProofTypes = isPresent(credentialConfigurationSupported.getProofTypesSupported());

        boolean holderBindingRequired = hasBindingMethods && hasProofTypes;
        log.debug("Holder binding evaluation for config id [{}]: cryptographicBindingMethodsSupported present={}, " +
                        "proofTypesSupported present={}, holderBindingRequired={}",
                credentialConfigurationSupported.getId(), hasBindingMethods, hasProofTypes, holderBindingRequired);

        return holderBindingRequired;
    }

    private boolean isPresent(List<String> values) {
        return values != null && !values.isEmpty();
    }

    private boolean isPresent(Map<String, Object> values) {
        return values != null && !values.isEmpty();
    }
}