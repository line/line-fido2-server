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

package com.linecorp.line.auth.fido.fido2.server.mds.service;

import java.io.IOException;

import okhttp3.ResponseBody;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

public class MdsProtocolClient {
    private final MdsProtocolService service;

    public MdsProtocolClient(String baseUrl) {
        Retrofit retrofit = new Retrofit
                .Builder()
                .baseUrl(baseUrl)
                .addConverterFactory(JacksonConverterFactory.create())
                .build();

        service = retrofit.create(MdsProtocolService.class);
    }

    public void fetchAsyncMetadataToc(String url, Callback<ResponseBody> callback) {
        service.fetchMetadataToc(url).enqueue(callback);
    }

    public void fetchAsyncMetadata(String url, Callback<ResponseBody> callback) {
        service.fetchMetadata(url).enqueue(callback);
    }

    public Response<ResponseBody>  fetchSyncMetadataToc(String url) throws IOException {
        return service.fetchMetadataToc(url).execute();
    }

    public Response<ResponseBody> fetchSyncMetadata(String url) throws IOException {
        return service.fetchMetadata(url).execute();
    }
}
