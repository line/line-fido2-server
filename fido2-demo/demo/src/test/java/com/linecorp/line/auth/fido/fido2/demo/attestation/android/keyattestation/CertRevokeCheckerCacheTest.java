/*
 * Copyright 2024 LY Corporation
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

package com.linecorp.line.auth.fido.fido2.demo.attestation.android.keyattestation;

import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.RevokeCheckerClient;
import com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation.RevokedEntries;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import retrofit2.Response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SpringBootTest
class CertRevokeCheckerCacheTest {

    private static final String REVOKE_STATUS_URL = "attestation/status";

    @SpyBean
    private RevokeCheckerClient revokeCheckerClient;

    @Test
    void verify_fetch_android_key_attestation_revoke_list_caching() throws Exception {

        Response<RevokedEntries> response1 = revokeCheckerClient.fetchAndroidKeyAttestationRevokeList(REVOKE_STATUS_URL);
        assertThat(response1.body()).isNotNull();
        assertThat(response1.body().getEntries()).isNotEmpty();

        Response<RevokedEntries> response2 = revokeCheckerClient.fetchAndroidKeyAttestationRevokeList(REVOKE_STATUS_URL);
        assertThat(response2.body()).isNotNull();
        assertThat(response2.body().getEntries()).isNotEmpty();
        
        verify(revokeCheckerClient, times(1)).fetchAndroidKeyAttestationRevokeList(anyString());
    }
}
