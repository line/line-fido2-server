/*
 * Copyright 2024-2026 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.base.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.linecorp.line.auth.fido.fido2.server.attestation.AttestationVerifierFactory;
import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.RevokeCheckerClient;
import com.linecorp.line.auth.fido.fido2.server.property.Fido2Properties;
import com.linecorp.line.auth.fido.fido2.server.service.AttestationService;
import com.linecorp.line.auth.fido.fido2.server.service.AttestationServiceImpl;
import com.linecorp.line.auth.fido.fido2.server.service.ChallengeService;
import com.linecorp.line.auth.fido.fido2.server.service.ChallengeServiceImpl;
import com.linecorp.line.auth.fido.fido2.server.service.MetadataService;
import com.linecorp.line.auth.fido.fido2.server.service.RpService;
import com.linecorp.line.auth.fido.fido2.server.service.SessionService;
import com.linecorp.line.auth.fido.fido2.server.service.UserKeyService;
import com.linecorp.line.auth.fido.fido2.server.service.VendorSpecificMetadataService;

@Configuration
@EntityScan(basePackages = {"com.linecorp.line.auth.fido.fido2.base.entity"})
@EnableJpaRepositories(basePackages = {"com.linecorp.line.auth.fido.fido2.base.repository",})
@ComponentScan(basePackages = {
        "com.linecorp.line.auth.fido.fido2.server.property",
        "com.linecorp.line.auth.fido.fido2.server.service",
        "com.linecorp.line.auth.fido.fido2.server.attestation",
        "com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation",
        "com.linecorp.line.auth.fido.fido2.server.config",
        "com.linecorp.line.auth.fido.fido2.base.service",
        "com.linecorp.line.auth.fido.fido2.base.config",
})
@EnableConfigurationProperties(Fido2Properties.class)
public class BaseAutoConfiguration {

    @Bean
    public ChallengeService ChallengeService(final RpService rpService,
                                             final UserKeyService userKeyService,
                                             final SessionService sessionService,
                                             final Fido2Properties fido2Properties
    ) {
        return new ChallengeServiceImpl(rpService,
                                        userKeyService,
                                        sessionService,
                                        fido2Properties
        );
    }

    @Bean
    public AttestationService attestationService(
            final MetadataService metadataService,
            final VendorSpecificMetadataService vendorSpecificMetadataService,
            final AttestationVerifierFactory attestationVerifierFactory,
            final RevokeCheckerClient revokeCheckerClient,
            final Fido2Properties fido2Properties
    ) {
        return new AttestationServiceImpl(
                metadataService,
                vendorSpecificMetadataService,
                attestationVerifierFactory,
                revokeCheckerClient,
                fido2Properties
        );
    }
}
