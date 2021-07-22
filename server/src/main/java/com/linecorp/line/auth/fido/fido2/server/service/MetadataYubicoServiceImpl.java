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

package com.linecorp.line.auth.fido.fido2.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.server.entity.MetadataYubicoEntity;
import com.linecorp.line.auth.fido.fido2.server.model.metadata.yubico.MetadataObject;
import com.linecorp.line.auth.fido.fido2.server.repository.MetadataYubicoRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
public class MetadataYubicoServiceImpl implements MetadataYubicoService {
    private final ObjectMapper objectMapper;
    private final MetadataYubicoRepository metadataYubicoRepository;

    @Autowired
    public MetadataYubicoServiceImpl(
            ObjectMapper objectMapper,
            MetadataYubicoRepository metadataYubicoRepository) {
        this.objectMapper = objectMapper;
        this.metadataYubicoRepository = metadataYubicoRepository;
    }

    @Override
    public MetadataObject getLatestMetadata() {
        MetadataYubicoEntity metadataYubicoEntity = metadataYubicoRepository.findFirstByOrderByIdDesc();

        String content = metadataYubicoEntity.getContent();
        MetadataObject metadataObject = null;
        try {
            metadataObject = objectMapper.readValue(content, MetadataObject.class);
        } catch (IOException e) {
            log.warn("Error parsing metadata: " + e.getMessage(), e);
        }
        return metadataObject;
    }
}
