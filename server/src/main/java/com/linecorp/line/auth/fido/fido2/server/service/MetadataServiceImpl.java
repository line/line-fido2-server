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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.linecorp.line.auth.fido.fido2.server.entity.MetadataEntity;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.repository.MetadataRepository;
import com.linecorp.line.auth.fido.uaf.common.metadata.MetadataStatement;

@Service
public class MetadataServiceImpl implements MetadataService {
    private final ObjectMapper objectMapper;
    private final MetadataRepository metadataRepository;

    @Autowired
    public MetadataServiceImpl(ObjectMapper objectMapper, MetadataRepository metadataRepository) {
        this.objectMapper = objectMapper;
        this.metadataRepository = metadataRepository;
    }

    @Override
    public MetadataStatement getMetadataStatementWithAaguid(String aaguid) {
        MetadataEntity metadataEntity = metadataRepository.findByAaguid(aaguid);
        if (metadataEntity != null) {
            try {
                String metadataContent = metadataEntity.getContent();
                return objectMapper.readValue(metadataContent, MetadataStatement.class);
            } catch (IOException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.METADATA_JSON_DESERIALIZE_FAIL, e);
            }
        }
        return null;
    }

    @Override
    public List<MetadataStatement> getAllU2FMetadataStatements() {
        List<MetadataStatement> metadataStatementList = new ArrayList<>();
        metadataRepository.findAllByAaguidIsNull().forEach(m -> {
            try {
                metadataStatementList.add(objectMapper.readValue(m.getContent(), MetadataStatement.class));
            } catch (IOException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.METADATA_JSON_DESERIALIZE_FAIL, e);
            }
        });
        return metadataStatementList;
    }

    @Override
    public List<MetadataStatement> getAllMetadataStatements() {
        List<MetadataStatement> metadataStatementList = new ArrayList<>();
        metadataRepository.findAll().forEach(m -> {
            try {
                metadataStatementList.add(objectMapper.readValue(m.getContent(), MetadataStatement.class));
            } catch (IOException e) {
                throw new FIDO2ServerRuntimeException(InternalErrorCode.METADATA_JSON_DESERIALIZE_FAIL, e);
            }
        });
        return metadataStatementList;
    }
}
