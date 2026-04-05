/*
 * Copyright 2026 LY Corporation
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

package com.linecorp.line.auth.fido.fido2.server.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialParameters;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRpEntity;
import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionRequest;
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialUserEntity;
import com.linecorp.line.auth.fido.fido2.server.model.Session;
import com.linecorp.line.auth.fido.fido2.server.property.Fido2Properties;
import com.linecorp.line.auth.fido.fido2.server.property.Fido2Properties.RegistrationProperties;

class ChallengeServiceImplTest {

    private final RpService rpService = mock();
    private final UserKeyService userKeyService = mock();
    private final SessionService sessionService = mock();

    private static final long SESSION_TTL_MILLIS = 10000;
    private static final String RP_ID = "example.com";

    @BeforeEach
    void setUp() {
        final PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity();
        rpEntity.setId(RP_ID);
        rpEntity.setName("Example");

        when(rpService.contains(RP_ID)).thenReturn(true);
        when(rpService.get(RP_ID)).thenReturn(rpEntity);
        when(userKeyService.getWithUserId(anyString(), anyString())).thenReturn(Collections.emptyList());

        final Session session = new Session();
        session.setId("test-session-id");
        when(sessionService.createSessionData()).thenReturn(session);
    }

    private ChallengeServiceImpl createCut(Fido2Properties fido2Properties) {
        return new ChallengeServiceImpl(rpService, userKeyService, sessionService, fido2Properties);
    }

    private static RegOptionRequest createRegOptionRequest() {
        final PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity();
        rp.setId(RP_ID);
        rp.setName("Example");

        final ServerPublicKeyCredentialUserEntity user = new ServerPublicKeyCredentialUserEntity();
        user.setId("dXNlci0x");
        user.setName("user@example.com");
        user.setDisplayName("User");

        return RegOptionRequest.builder()
                               .rp(rp)
                               .user(user)
                               .build();
    }

    @Test
    void getRegChallenge_emptyAllowedAlgorithms_returnsAllAlgorithms() {
        final Fido2Properties fido2Properties = new Fido2Properties(
                SESSION_TTL_MILLIS,
                true,
                true,
                new RegistrationProperties(List.of())
        );
        final ChallengeServiceImpl cut = createCut(fido2Properties);

        final RegOptionResponse response = cut.getRegChallenge(createRegOptionRequest());

        final List<PublicKeyCredentialParameters> pubKeyCredParams = response.getPubKeyCredParams();
        assertEquals(COSEAlgorithm.values().length, pubKeyCredParams.size());

        final Set<Long> returnedValues = pubKeyCredParams.stream()
                                                         .map(p -> p.getAlg().getValue())
                                                         .collect(Collectors.toSet());
        for (COSEAlgorithm alg : COSEAlgorithm.values()) {
            assertTrue(returnedValues.contains((long) alg.getValue()),
                    "Expected algorithm " + alg.getName() + " to be included");
        }
    }

    @Test
    void getRegChallenge_specificAllowedAlgorithms_returnsOnlyAllowedAlgorithms() {
        final Fido2Properties fido2Properties = new Fido2Properties(
                SESSION_TTL_MILLIS,
                true,
                true,
                new RegistrationProperties(List.of("ES256", "RS256"))
        );
        final ChallengeServiceImpl cut = createCut(fido2Properties);

        final RegOptionResponse response = cut.getRegChallenge(createRegOptionRequest());

        final List<PublicKeyCredentialParameters> pubKeyCredParams = response.getPubKeyCredParams();
        assertEquals(fido2Properties.getRegistration().getAllowedAlgorithms().size(), pubKeyCredParams.size());

        final Set<Long> returnedValues = pubKeyCredParams.stream()
                                                         .map(p -> p.getAlg().getValue())
                                                         .collect(Collectors.toSet());
        for (String algName : fido2Properties.getRegistration().getAllowedAlgorithms()) {
            final COSEAlgorithm expected = COSEAlgorithm.valueOf(algName);
            assertTrue(returnedValues.contains((long) expected.getValue()),
                       "Expected algorithm " + algName + " to be included");
        }
    }
}
