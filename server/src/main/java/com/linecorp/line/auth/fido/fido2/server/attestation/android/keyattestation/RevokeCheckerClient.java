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
import org.springframework.cache.annotation.Cacheable;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import java.io.IOException;

public class RevokeCheckerClient {
    @Cacheable("androidKeyAttestationRevokeList")
    public Response<ResponseBody> fetchAndroidKeyAttestationRevokeList(String url) throws IOException {
        Retrofit retrofit = new Retrofit
                .Builder()
                .baseUrl("https://android.googleapis.com/")
                .addConverterFactory(JacksonConverterFactory.create())
                .build();

        return retrofit.create(RevokeCheckerService.class).fetchRevokeList(url).execute();
    }
}
