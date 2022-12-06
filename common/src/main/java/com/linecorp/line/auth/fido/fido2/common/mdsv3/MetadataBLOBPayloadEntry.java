/*
 * Copyright 2022 LINE Corporation
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

package com.linecorp.line.auth.fido.fido2.common.mdsv3;

import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.BiometricStatusReport;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.MetadataStatement;
import lombok.Data;

import java.util.List;

@Data
public class MetadataBLOBPayloadEntry {
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private MetadataStatement metadataStatement;
    private List<BiometricStatusReport> biometricStatusReports;

    private List<StatusReport> statusReports;
    private String timeOfLastStatusChange;
    private String rogueListURL;
    private StringBuilder rogueListHash;
}
