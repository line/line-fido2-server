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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

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
    void getRegChallenge_emptyAllowedAlgorithms_returnsAllAlgorithmsInEnumOrder() {
        final Fido2Properties fido2Properties = new Fido2Properties(
                SESSION_TTL_MILLIS,
                true,
                true,
                new RegistrationProperties(List.of())
        );
        final ChallengeServiceImpl cut = createCut(fido2Properties);

        final RegOptionResponse response = cut.getRegChallenge(createRegOptionRequest());

        final COSEAlgorithm[] expectedAlgorithms = COSEAlgorithm.values();
        final List<PublicKeyCredentialParameters> pubKeyCredParams = response.getPubKeyCredParams();
        assertEquals(expectedAlgorithms.length, pubKeyCredParams.size());

        int index = 0;
        for (COSEAlgorithm expectedAlgorithm : expectedAlgorithms) {
            final PublicKeyCredentialParameters actualParameter = pubKeyCredParams.get(index);
            assertEquals(expectedAlgorithm.getValue(), actualParameter.getAlg().getValue());
            index++;
        }
    }

    @Test
    void getRegChallenge_specificAllowedAlgorithms_returnsOnlyAllowedAlgorithmsInConfiguredOrder() {
        final Fido2Properties fido2Properties = new Fido2Properties(
                SESSION_TTL_MILLIS,
                true,
                true,
                new RegistrationProperties(List.of("RS512", "ES256", "ES256K"))
        );
        final ChallengeServiceImpl cut = createCut(fido2Properties);

        final RegOptionResponse response = cut.getRegChallenge(createRegOptionRequest());

        final List<PublicKeyCredentialParameters> pubKeyCredParams = response.getPubKeyCredParams();
        assertEquals(fido2Properties.getRegistration().getAllowedAlgorithms().size(), pubKeyCredParams.size());
        assertEquals(COSEAlgorithm.RS512.getValue(), pubKeyCredParams.get(0).getAlg().getValue());
        assertEquals(COSEAlgorithm.ES256.getValue(), pubKeyCredParams.get(1).getAlg().getValue());
        assertEquals(COSEAlgorithm.ES256K.getValue(), pubKeyCredParams.get(2).getAlg().getValue());
    }
}
