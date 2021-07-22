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

package com.linecorp.line.auth.fido.fido2.server.mds;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests;
import com.linecorp.line.auth.fido.fido2.server.config.MdsConfig;
import com.linecorp.line.auth.fido.fido2.server.config.MdsInfo;
import com.linecorp.line.auth.fido.fido2.server.entity.MetadataEntity;
import com.linecorp.line.auth.fido.fido2.server.entity.MetadataTocEntity;
import com.linecorp.line.auth.fido.fido2.server.mds.service.MdsProtocolClient;
import com.linecorp.line.auth.fido.fido2.server.repository.MetadataRepository;
import com.linecorp.line.auth.fido.fido2.server.repository.MetadataTocRepository;
import com.linecorp.line.auth.fido.fido2.server.util.CertPathUtil;
import com.linecorp.line.auth.fido.fido2.server.util.CertificateUtil;
import com.linecorp.line.auth.fido.uaf.common.mds.AuthenticatorStatus;
import com.linecorp.line.auth.fido.uaf.common.mds.MetadataTOCPayload;
import com.linecorp.line.auth.fido.uaf.common.mds.MetadataTOCPayloadEntry;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Slf4j
@Component
public class MdsFetchTask implements ApplicationListener<ApplicationReadyEvent> {
    private static final String ALGORITHM_RS256 = "RS256";
    private static final String ALGORITHM_RS384 = "RS384";
    private static final String ALGORITHM_RS512 = "RS512";
    private static final String ALGORITHM_ES256 = "ES256";
    private static final String ALGORITHM_ES384 = "ES384";
    private static final String ALGORITHM_ES512 = "ES512";

    private final MetadataRepository metadataRepository;
    private final MetadataTocRepository metadataTocRepository;
    private final MdsProtocolClient mdsProtocolClient;

    private final Queue<MdsInfo> metadataSourceQueue = new LinkedList<>();

    private boolean enableMds;

    @Autowired
    public MdsFetchTask(MdsConfig mdsConfig, MetadataRepository metadataRepository, MetadataTocRepository metadataTocRepository) {
        this.metadataRepository = metadataRepository;
        this.metadataTocRepository = metadataTocRepository;
        this.enableMds = mdsConfig.isEnableMds();

        mdsProtocolClient = new MdsProtocolClient(mdsConfig.getSources().get(0).getEndpoint());

        if(enableMds) {
            metadataSourceQueue.addAll(mdsConfig.getSources());
        }
    }

    public void refreshMetadata() {
        MdsInfo mdsInfo = metadataSourceQueue.poll();
        if (mdsInfo == null || !mdsInfo.isEnabled()) {
            return;
        }
        log.info("Handle MDS with following source: {}", mdsInfo);
        String mdsSourceEndpoint = mdsInfo.getEndpoint();
        if ("fido-mds-v2".equals(mdsInfo.getName()) && mdsInfo.getAccessToken() != null ) {
            mdsSourceEndpoint += "?token=" + mdsInfo.getAccessToken();
        } else if (mdsInfo.getName().contains("conformance")) {
            mdsSourceEndpoint += mdsInfo.getAccessToken();
        }
        log.info("Start fetching Metadata TOC");
        mdsProtocolClient.fetchAsyncMetadataToc(mdsSourceEndpoint, new Callback<ResponseBody>() {
            @Override
            public void onResponse(Call<ResponseBody> call, Response<ResponseBody> response) {
                if (response.isSuccessful()) {
                    log.debug("Metadata successfully fetched");
                    String metadataToc;
                    String url = call.request().url().toString();
                    try {
                        if (response.body() == null) {
                            log.error("Metadata TOC fetch failed");
                            return;
                        }
                        metadataToc = response.body().string();
                        // handleMetadataToc
                        MetadataTOCResult result = handleMetadataToc(url, metadataToc, mdsInfo);
                        log.info("Metadata TOC from MDS ({}) handling result: {}", mdsInfo.getName(), result);

                    } catch (IOException | CertificateException e) {
                        log.warn("Error parsing metadata TOC: " + e.getMessage(), e);
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

    private MetadataTOCResult handleMetadataToc(String url, String metadataToc, MdsInfo mdsInfo) throws CertificateException {
        log.info("Start handling Metadata TOC");

        int updatedCount = 0, totalCount = 0;
        int uafEntryCount = 0, u2fEntryCount = 0, fido2EntryCount = 0;
        DecodedJWT decodedJWT = JWT.decode(metadataToc);
        List<Certificate> certificateChain = new ArrayList<>();
        Claim x5u = decodedJWT.getHeaderClaim("x5u");

        String encodedMetadataTocPayload = decodedJWT.getPayload();

        // decode payload
        ObjectMapper objectMapper = new ObjectMapper();
        MetadataTOCPayload metadataTOCPayload;
        try {
            metadataTOCPayload = objectMapper.readValue(Base64.getUrlDecoder().decode(encodedMetadataTocPayload), MetadataTOCPayload.class);
        } catch (IOException e) {
            return MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(totalCount)
                    .updatedCount(updatedCount)
                    .reason("Json parsing error of Metadata TOC Payload")
                    .build();
        }

        log.info("Metadata TOC Payload: {}", metadataTOCPayload);

        totalCount = metadataTOCPayload.getEntries().size();

        // check no and compare with previous
        MetadataTocEntity metadataTocEntity = metadataTocRepository.findFirstByMetadataSourceOrderByNoDesc(mdsInfo.getName());

        if (metadataTocEntity != null) {
            if (metadataTocEntity.getId() >= metadataTOCPayload.getNo()) {
                // already up to date
                return MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(totalCount)
                        .updatedCount(updatedCount)
                        .reason("Local cached data is already up to date")
                        .build();
            }
        }

        if (!x5u.isNull()) {
            // refer x5u
            String x509UrlString = x5u.asString();

            URL x509Url, tocUrl;
            try {
                x509Url = new URL(x509UrlString);
                tocUrl = new URL(url);

            } catch (MalformedURLException e) {
                return MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(totalCount)
                        .updatedCount(updatedCount)
                        .reason("URL for x5u is not valid")
                        .build();
            }

            if (!x509Url.getHost().equals(tocUrl.getHost())) {
                return MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(totalCount)
                        .updatedCount(updatedCount)
                        .reason("x5u origin differs to Metadata TOC origin")
                        .build();
            }

            // retrieve x509 certificate or certificate chain (PEM)
            String pemEncoded = ""; // need to get from x5u url
            String[] certificateParts = pemEncoded.split("-----END CERTIFICATE-----");
            for (String certificate : certificateParts) {
                certificateChain.add(
                        CertificateUtil.getCertificate(certificate.replaceAll("\"-----BEGIN CERTIFICATE-----\"", "").replaceAll("\n", "")));
            }
        } else {
            // get chain with x5c
            Claim x5c = decodedJWT.getHeaderClaim("x5c");

            if (!x5c.isNull()) {
                // refer x5c
                List<String> derEncodedCertificates = x5c.asList(String.class);

                if (derEncodedCertificates == null ||
                    derEncodedCertificates.isEmpty()) {
                    // error
                    return MetadataTOCResult
                            .builder()
                            .result(false)
                            .totalCount(totalCount)
                            .updatedCount(updatedCount)
                            .reason("x5c is empty")
                            .build();
                } else {
                    certificateChain = CertificateUtil.getCertificatesFromStringList(derEncodedCertificates);
                }

            } else {
                // consider trust anchor as signing chain
                certificateChain = CertificateUtil.getCertificatesFromStringList(mdsInfo.getRootCertificates());
            }
        }


        Set<TrustAnchor> trustAnchors =  CertificateUtil.getTrustAnchors(mdsInfo.getRootCertificates());
        try {
            boolean result = CertPathUtil.validate(certificateChain, trustAnchors, true);

            if (!result) {
                return MetadataTOCResult
                        .builder()
                        .result(false)
                        .totalCount(totalCount)
                        .updatedCount(updatedCount)
                        .reason("Chain validation fail")
                        .build();
            }
        } catch (GeneralSecurityException e) {
            return MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(totalCount)
                    .updatedCount(updatedCount)
                    .reason("Chain validation exception: " + e.getMessage())
                    .build();
        }
        log.info("Chain validation success");

        // verify signature
        Certificate signingCertificate = certificateChain.get(0);
        PublicKey publicKey = signingCertificate.getPublicKey();

        // get jwt signature algorithm and hash algorithm
        String algorithm = decodedJWT.getAlgorithm();
        Algorithm signatureAlgorithm;
        String hashAlgorithm;
        if (ALGORITHM_RS256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
            hashAlgorithm = "SHA256";
        } else if (ALGORITHM_RS384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA384((RSAPublicKey) publicKey, null);
            hashAlgorithm = "SHA384";
        } else if (ALGORITHM_RS512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.RSA512((RSAPublicKey) publicKey, null);
            hashAlgorithm = "SHA512";
        } else if (ALGORITHM_ES256.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA256((ECPublicKey) publicKey, null);
            hashAlgorithm = "SHA256";
        } else if (ALGORITHM_ES384.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA384((ECPublicKey) publicKey, null);
            hashAlgorithm = "SHA384";
        } else if (ALGORITHM_ES512.equals(algorithm)) {
            signatureAlgorithm = Algorithm.ECDSA512((ECPublicKey) publicKey, null);
            hashAlgorithm = "SHA512";
        } else {
            return MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(totalCount)
                    .updatedCount(updatedCount)
                    .reason("Not supported signature algorithm: " + algorithm)
                    .build();
        }
        JWTVerifier jwtVerifier = JWT.require(signatureAlgorithm).build();
        try {
            jwtVerifier.verify(metadataToc);
        } catch (AlgorithmMismatchException | SignatureVerificationException | TokenExpiredException | InvalidClaimException e) {
            return MetadataTOCResult
                    .builder()
                    .result(false)
                    .totalCount(totalCount)
                    .updatedCount(updatedCount)
                    .reason("Signature verification fail: " + e.getMessage())
                    .build();
        }

        // toc is valid and new version
        // store data
        metadataTocRepository.save(
                new MetadataTocEntity(null, mdsInfo.getName(), metadataTOCPayload.getNo(), metadataTOCPayload.getLegalHeader(), metadataTOCPayload.getNextUpdate(), encodedMetadataTocPayload));


        // iterate all payload entry
        int metadataCount = metadataTOCPayload.getEntries().size();
        log.info("MDS Registered metadata count: ", metadataCount);
        for (MetadataTOCPayloadEntry entry : metadataTOCPayload.getEntries()) {
            log.info("Metadata TOC Payload Entry: {}", entry);
            // check status report, timeOfLastStatusChange has been changed comparing to local cache
            // find metadata from db and compare it
            if (!isAcceptableStatus(entry.getStatusReports().get(0).getStatus())) {
                log.debug("Ignore entry due to status: {}", entry.getStatusReports().get(0).getStatus());
                continue;
            }

            MetadataEntity localMetadataEntity = null;
            if (entry.getAaid() != null) {
                // uaf case, ignore it
                uafEntryCount++;
                log.debug("Ignore UAF metadata entry");
                continue;
            }
            if (entry.getAaguid() != null) {
                // fido2 case
                fido2EntryCount++;
                localMetadataEntity = metadataRepository.findByAaguid(entry.getAaguid());
            }
            if (entry.getAttestationCertificateKeyIdentifiers() != null &&
                !entry.getAttestationCertificateKeyIdentifiers().isEmpty()) {
                // u2f case
                u2fEntryCount++;
            }

            if (localMetadataEntity == null ||
                (localMetadataEntity != null && !entry.getTimeOfLastStatusChange().equals(
                        localMetadataEntity.getTimeOfLastStatusChange()))) {
                // new entry
                // or download metadata with url and check hash, if valid update it
                try {
                    String metadataStatementUrl = entry.getUrl();
                    if ("fido-mds-v2".equals(mdsInfo.getName()) && mdsInfo.getAccessToken() != null ) {
                        metadataStatementUrl += "/?token=" + mdsInfo.getAccessToken();
                    }
                    Response<ResponseBody> response = mdsProtocolClient.fetchSyncMetadata(metadataStatementUrl);

                    if (response.isSuccessful() && response.body() != null) {
                        String encodedMetadataStatement = response.body().string();

                        // check hash value with signature algorithm of JWT
                        byte[] digest = Digests.digest(hashAlgorithm, encodedMetadataStatement.getBytes());

                        if (entry.getHash().equals(
                                Base64.getUrlEncoder().withoutPadding().encodeToString(digest))) {
                            // update metadata
                            updatedCount++;
                            String metdatadata = new String(Base64.getUrlDecoder().decode(encodedMetadataStatement));
                            log.info("Metadata: {}", metdatadata);
                            MetadataEntity.MetadataEntityBuilder builder = MetadataEntity
                                    .builder()
                                    .aaguid(entry.getAaguid())
                                    .content(metdatadata)
                                    .statusReports(entry.getStatusReports().toString())
                                    .timeOfLastStatusChange(entry.getTimeOfLastStatusChange());

                            // if it is existing one, just update it
                            if (localMetadataEntity != null) {
                                builder.id(localMetadataEntity.getId());
                            }
                            MetadataEntity metadataEntity = builder.build();
                            metadataRepository.save(metadataEntity);
                        } else {
                            // ignore it
                            // not valid entry
                            log.info("Ignore entry (hash not matched)");
                            continue;
                        }
                    } else {
                        // http error
                        continue;
                    }
                } catch (IOException e) {
                    log.warn("Metadata fectch error: " + e.getMessage(), e);
                    continue;
                }
            } else {
                // skip it, already latest one
                log.info("Skip entry, already latest one");
                continue;
            }
        }

        log.info("Finish handling Metadata TOC");

        return MetadataTOCResult
                .builder()
                .result(true)
                .totalCount(totalCount)
                .updatedCount(updatedCount)
                .u2fEntryCount(u2fEntryCount)
                .uafEntryCount(uafEntryCount)
                .fido2EntryCount(fido2EntryCount)
                .build();
    }

    /**
     * check whether the entry is acceptable or not (this is server policy, we implement this function only for conformance tool
     * @param authenticatorStatus
     * @return
     */
    private boolean isAcceptableStatus(AuthenticatorStatus authenticatorStatus) {
        return authenticatorStatus != AuthenticatorStatus.USER_VERIFICATION_BYPASS &&
               authenticatorStatus != AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE &&
               authenticatorStatus != AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE &&
               authenticatorStatus != AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if(enableMds) {
            refreshMetadata();
        }
    }
}
