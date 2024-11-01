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

package com.linecorp.line.auth.fido.fido2.server.mds;

import com.linecorp.line.auth.fido.fido2.server.mds.network.MdsProtocolClient;
import lombok.extern.slf4j.Slf4j;
import okhttp3.ResponseBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.Queue;

@Slf4j
@Component
public class MdsFetchTask implements ApplicationListener<ApplicationReadyEvent> {

    private final MdsProtocolClient mdsProtocolClient;

    private final MdsService mdsService;

    private final Queue<MdsInfo> metadataSourceQueue = new LinkedList<>();

    private final boolean enableMds;

    @Autowired
    public MdsFetchTask(MdsConfig mdsConfig, MdsService mdsService) {
        this.enableMds = mdsConfig.isEnableMds();
        this.mdsService = mdsService;

        mdsProtocolClient = new MdsProtocolClient(mdsConfig.getSources().get(0).getEndpoint());

        if (enableMds) {
            metadataSourceQueue.addAll(mdsConfig.getSources());
        }
    }

    private void refreshMetadata() {
        MdsInfo mdsInfo = metadataSourceQueue.poll();
        if (mdsInfo == null || !mdsInfo.isEnabled()) {
            return;
        }
        log.info("Handle MDS with following source: {}", mdsInfo);
        log.info("Start fetching Metadata TOC");
        mdsProtocolClient.fetchAsyncMetadataToc(mdsInfo.getEndpoint(), new Callback<ResponseBody>() {
            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {
                if (response.isSuccessful()) {
                    log.debug("Metadata successfully fetched");
                    try {
                        if (response.body() == null) {
                            log.error("Metadata TOC fetch failed");
                            return;
                        }
                        String metadataToc = response.body().string();
                        // handleMetadataToc
                        MetadataTOCResult result = handleMetadataToc(metadataToc, mdsInfo);
                        log.debug("Metadata TOC from MDS ({}) handling result: {}", mdsInfo.getName(), result);

                    } catch (IOException | CertificateException e) {
                        log.error("Error parsing metadata TOC: " + e.getMessage(), e);
                    } catch (MdsV3MetadataException e) {
                        log.error("Error handling metadata TOC: " + e.metadataTOCResult);
                    }

                } else {
                    log.error("Metadata TOC fetch failed");
                }
            }

            @Override
            public void onFailure(Call<ResponseBody> call, Throwable t) {
                log.error("Fetching Metadata TOC failure due to connection problem");
                refreshMetadata();
            }
        });
        refreshMetadata();
    }

    private MetadataTOCResult handleMetadataToc(String metadataToc, MdsInfo mdsInfo) throws CertificateException, MdsV3MetadataException {
        log.info("Start handling Metadata TOC");
        return mdsService.handle(metadataToc, mdsInfo);
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (enableMds) {
            refreshMetadata();
        }
    }
}
