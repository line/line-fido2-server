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

package com.linecorp.line.auth.fido.fido2.base.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.base.entity.MetadataEntity;
import com.linecorp.line.auth.fido.fido2.base.repository.MetadataRepository;
import com.linecorp.line.auth.fido.fido2.base.repository.MetadataTocRepository;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.AuthenticatorStatus;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.MetadataBLOBPayload;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.MetadataBLOBPayloadEntry;
import com.linecorp.line.auth.fido.fido2.base.entity.MetadataTocEntity;
import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.mds.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;

@Slf4j
@Component
public class MdsV3ServiceImpl implements MdsService {

    private final MetadataRepository metadataRepository;

    private final MetadataTocRepository metadataTocRepository;

    public MdsV3ServiceImpl(MetadataRepository metadataRepository, MetadataTocRepository metadataTocRepository) {
        this.metadataRepository = metadataRepository;
        this.metadataTocRepository = metadataTocRepository;
    }

    @Override
    public MetadataTOCResult handle(String metadataToc, MdsInfo mdsInfo) throws CertificateException, MdsV3MetadataException {
        MetadataBLOBPayload metadataBLOBPayload = createMetadataBLOBPayload(metadataToc);

        checkLatestDataExist(metadataTocRepository.findFirstByMetadataSourceOrderByNoDesc(mdsInfo.getName()), metadataBLOBPayload);
        MdsV3MetadataCertificateUtil.verifyCertificate(metadataToc, mdsInfo, metadataBLOBPayload);
        return handleMetadata(metadataToc, mdsInfo, metadataBLOBPayload);
    }

    private MetadataTOCResult handleMetadata(String metadataToc, MdsInfo mdsInfo, MetadataBLOBPayload metadataBLOBPayload) {
        saveMetaDataToc(metadataToc, mdsInfo, metadataBLOBPayload, metadataTocRepository);
        return processBlobPayload(metadataBLOBPayload, metadataRepository);
    }

    private static MetadataBLOBPayload createMetadataBLOBPayload(String metadataToc) throws MdsV3MetadataException {

        DecodedJWT decodedJWT = JWT.decode(metadataToc);
        String encodedMetadataTocPayload = decodedJWT.getPayload();

        // decode payload
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        MetadataBLOBPayload metadataBLOBPayload;
        try {
            metadataBLOBPayload = objectMapper.readValue(Base64.getUrlDecoder().decode(encodedMetadataTocPayload), MetadataBLOBPayload.class);
        } catch (IOException e) {
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(0)
                    .updatedCount(0)
                    .reason("Json parsing error of Metadata TOC Payload")
                    .build());
        }

        return metadataBLOBPayload;
    }

    private static void checkLatestDataExist(MetadataTocEntity metadataTocEntity, MetadataBLOBPayload metadataBLOBPayload) throws MdsV3MetadataException {
        // check no and compare with previous
        if (metadataTocEntity != null && (metadataTocEntity.getId() >= metadataBLOBPayload.getNo())) {
            // already up to date
            throw new MdsV3MetadataException(MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(metadataBLOBPayload.getEntries().size())
                    .updatedCount(0)
                    .reason("Local cached data is already up to date")
                    .build());
        }
    }

    private static void saveMetaDataToc(String metadataToc, MdsInfo mdsInfo, MetadataBLOBPayload metadataBLOBPayload, MetadataTocRepository metadataTocRepository) {
        metadataTocRepository.save(
                new MetadataTocEntity(null, mdsInfo.getName(), metadataBLOBPayload.getNo(), metadataBLOBPayload.getLegalHeader(), metadataBLOBPayload.getNextUpdate(), JWT.decode(metadataToc).getPayload()));
    }

    private static MetadataTOCResult processBlobPayload(MetadataBLOBPayload metadataBLOBPayload, MetadataRepository metadataRepository) {

        // iterate all payload entry
        log.info("MDS Registered metadata count: {}", metadataBLOBPayload.getEntries().size());

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        int updatedCount = 0;
        int uafEntryCount = 0;
        int u2fEntryCount = 0;
        int fido2EntryCount = 0;

        for (MetadataBLOBPayloadEntry entry : metadataBLOBPayload.getEntries()) {

            if (!isAcceptableStatus(entry.getStatusReports().get(0).getStatus())) {
                log.debug("Ignore entry due to status: {}", entry.getStatusReports().get(0).getStatus());
                continue;
            }

            if (isUAFEntry(entry.getAaid())) {
                uafEntryCount++;
                log.debug("Ignore UAF metadata entry");
                continue;
            }

            if (isU2FEntry(entry)) {
                u2fEntryCount++;
                log.debug("Ignore U2F metadata entry");
                continue;
            }

            MetadataEntity localMetadataEntity;
            if (isFIDO2Entry(entry.getAaguid())) {
                fido2EntryCount++;
                localMetadataEntity = metadataRepository.findByAaguid(entry.getAaguid());

                if (isNewEntry(entry, localMetadataEntity)) {
                    updatedCount++;

                    try {
                        saveMetadata(entry, localMetadataEntity, objectMapper.writeValueAsString(entry.getMetadataStatement()), metadataRepository, objectMapper);
                    } catch (JsonProcessingException e) {
                        log.error("Json parsing error of Metadata Statement: {}", entry.getMetadataStatement());
                        //Because of the possibility that the metadata format has been changed or broken, it is specifically delivered to the user as an FIDO2ServerRuntimeException.
                        throw new FIDO2ServerRuntimeException(InternalErrorCode.METADATA_JSON_PARSING_FAIL);
                    }

                } else {
                    log.info("Skip entry, already latest one");
                }
            }
        }

        log.info("Finish handling Metadata TOC");
        return MetadataTOCResult
                .builder()
                .result(true)
                .totalCount(metadataBLOBPayload.getEntries().size())
                .updatedCount(updatedCount)
                .u2fEntryCount(u2fEntryCount)
                .uafEntryCount(uafEntryCount)
                .fido2EntryCount(fido2EntryCount)
                .build();
    }

    private static void saveMetadata(MetadataBLOBPayloadEntry entry, MetadataEntity localMetadataEntity, String encodedMetadataStatement, MetadataRepository metadataRepository, ObjectMapper objectMapper) throws JsonProcessingException {

        MetadataEntity.MetadataEntityBuilder builder = MetadataEntity
                .builder()
                .aaguid(entry.getAaguid())
                .content(encodedMetadataStatement)
                .biometricStatusReports(ObjectUtils.isEmpty(entry.getBiometricStatusReports()) ? null : objectMapper.writeValueAsString(entry.getBiometricStatusReports()))
                .statusReports(ObjectUtils.isEmpty(entry.getStatusReports()) ? null : objectMapper.writeValueAsString(entry.getStatusReports()))
                .timeOfLastStatusChange(entry.getTimeOfLastStatusChange());

        // if it is existing one, just update it
        if (localMetadataEntity != null) {
            builder.id(localMetadataEntity.getId());
        }
        MetadataEntity metadataEntity = builder.build();
        metadataRepository.save(metadataEntity);
    }

    private static boolean isU2FEntry(MetadataBLOBPayloadEntry entry) {
        return entry.getAttestationCertificateKeyIdentifiers() != null &&
                !entry.getAttestationCertificateKeyIdentifiers().isEmpty();
    }

    private static boolean isFIDO2Entry(String aaguid) {
        return aaguid != null;
    }

    private static boolean isUAFEntry(String aaid) {
        return aaid != null;
    }

    private static boolean isNewEntry(MetadataBLOBPayloadEntry entry, MetadataEntity localMetadataEntity) {
        return localMetadataEntity == null || !entry.getTimeOfLastStatusChange().equals(
                localMetadataEntity.getTimeOfLastStatusChange());
    }

    /**
     * check whether the entry is acceptable or not (this is server policy, we implement this function only for conformance tool
     *
     * @param authenticatorStatus
     * @return
     */
    private static boolean isAcceptableStatus(AuthenticatorStatus authenticatorStatus) {
        // check status report, timeOfLastStatusChange has been changed comparing to local cache
        // find metadata from db and compare it
        return authenticatorStatus != AuthenticatorStatus.USER_VERIFICATION_BYPASS &&
                authenticatorStatus != AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE &&
                authenticatorStatus != AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE &&
                authenticatorStatus != AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE &&
                authenticatorStatus != AuthenticatorStatus.REVOKED;
    }
}
