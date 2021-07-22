/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import retrofit2.Response;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class CertRevokeCheckerCacheTest {

    private static final String REVOKE_STATUS_URL = "attestation/status";

    @Autowired
    private RevokeCheckerClient client;

    @Test
    public void fetchRevokeListCacheTest_Cached_AndroidKeyAttestation() throws IOException {

        long start = System.currentTimeMillis();
        Response<ResponseBody> bodyResponse = client.fetchAndroidKeyAttestationRevokeList(REVOKE_STATUS_URL);
        long end = System.currentTimeMillis();
        long uncachedDataFetchTime = end - start;

        assertThat(bodyResponse.isSuccessful()).isTrue();
        assertThat(uncachedDataFetchTime).isGreaterThan(100);

        long cachedStart1 = System.currentTimeMillis();
        Response<ResponseBody> cachedResponse1 = client.fetchAndroidKeyAttestationRevokeList(REVOKE_STATUS_URL);
        long cachedEnd1 = System.currentTimeMillis();
        long cachedDataFetchTime1 = cachedEnd1 - cachedStart1;

        assertThat(cachedResponse1.isSuccessful()).isTrue();
        assertThat(cachedDataFetchTime1).isLessThan(5);

        long cachedStart2 = System.currentTimeMillis();
        Response<ResponseBody> cachedResponse2 = client.fetchAndroidKeyAttestationRevokeList(REVOKE_STATUS_URL);
        long cachedEnd2 = System.currentTimeMillis();
        long cachedDataFetchTime2 = cachedEnd2 - cachedStart2;

        assertThat(cachedResponse2.isSuccessful()).isTrue();
        assertThat(cachedDataFetchTime2).isLessThan(5);
    }
}
