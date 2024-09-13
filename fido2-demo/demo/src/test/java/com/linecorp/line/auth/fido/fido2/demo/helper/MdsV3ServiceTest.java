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

package com.linecorp.line.auth.fido.fido2.demo.helper;

import com.linecorp.line.auth.fido.fido2.base.entity.MetadataEntity;
import com.linecorp.line.auth.fido.fido2.base.repository.MetadataRepository;
import com.linecorp.line.auth.fido.fido2.server.mds.MdsConfig;
import com.linecorp.line.auth.fido.fido2.server.mds.MdsInfo;
import com.linecorp.line.auth.fido.fido2.server.mds.MdsService;
import com.linecorp.line.auth.fido.fido2.server.mds.MdsV3MetadataException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;

import javax.transaction.Transactional;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

@Transactional
@Rollback
@SpringBootTest
class MdsV3ServiceTest {

    public static final int EXPECTED_METADATA_SIZE = 73;
    @Autowired
    private MdsService mdsService;

    private MdsConfig mdsConfig;

    private String metadataToc;

    private String mdsEndPointUrl;

    @Autowired
    private MetadataRepository metadataRepository;

    @BeforeEach
    void setUp() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();

        //This is a file that was actually downloaded from https://mds3.fidoalliance.org/ on October 28, 2022.
        File file = new File(classLoader.getResource("file/test_encoded_mds_v3_bob_data_.jwt").getFile());

        metadataToc = new String(Files.readAllBytes(Paths.get(file.getPath())));

        MdsInfo mdsInfo = new MdsInfo();
        mdsInfo.setEndpoint("https://mds3.fidoalliance.org");
        mdsInfo.setName("FIDO Metadata Service");
        mdsInfo.setEnabled(true);
        mdsInfo.setRootCertificates(Collections.emptyList());

        mdsConfig = new MdsConfig();
        mdsConfig.setSources(Collections.singletonList(mdsInfo));
        mdsEndPointUrl = mdsConfig.getSources().get(0).getEndpoint();
    }

    @Test
    void handleTestWithWrongRootCertificates() {

        //given
        Assertions.assertNotNull(metadataToc);
        Assertions.assertNotNull(mdsEndPointUrl);

        MdsInfo mdsInfo = mdsConfig.getSources().get(0);

        MdsInfo wrongMdsInfo = new MdsInfo();
        wrongMdsInfo.setEndpoint(mdsInfo.getEndpoint());
        String wrongCert = "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoXDTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4imsrfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYwHwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAwZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciWDcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XUYjdBz56jSA==";
        wrongMdsInfo.setRootCertificates(Collections.singletonList(wrongCert));
        wrongMdsInfo.setEnabled(mdsInfo.isEnabled());
        wrongMdsInfo.setName(mdsInfo.getName());

        //then
        Assertions.assertThrows(MdsV3MetadataException.class, () -> {
            //when
            mdsService.handle(metadataToc, wrongMdsInfo);
        });
    }

    @Disabled("Due to expiration issue of the test certificates")
    @Test
    void handleTest() throws CertificateException {

        //given
        Assertions.assertNotNull(metadataToc);
        Assertions.assertNotNull(mdsEndPointUrl);

        //when
        mdsService.handle(metadataToc, mdsConfig.getSources().get(0));

        //then
        Iterable<MetadataEntity> metadataEntityIterable = metadataRepository.findAll();
        List<MetadataEntity> metadataEntityList = (List<MetadataEntity>) metadataEntityIterable;
        Assertions.assertEquals(EXPECTED_METADATA_SIZE, metadataEntityList.size());
    }
}
