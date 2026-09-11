/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.dto.CredentialConfigurationSupported;

/**
 * Determines, purely from issuer metadata, whether holder binding (and therefore
 * proof validation) is required for a given credential configuration.
 * <p>
 * Per the OID4VCI spec, holder binding is optional and is signalled by the issuer
 * via {@code cryptographic_binding_methods_supported} and {@code proof_types_supported}.
 * Single responsibility: this evaluator only answers that yes/no question.
 */
public interface HolderBindingEvaluator {

    /**
     * @param credentialConfigurationSupported the resolved credential configuration metadata
     *                                          for the requested credential_configuration_id/scope.
     * @return true if holder binding is required (both metadata attributes are present and
     *         non-empty), false otherwise.
     */
    boolean isHolderBindingRequired(CredentialConfigurationSupported credentialConfigurationSupported);
}