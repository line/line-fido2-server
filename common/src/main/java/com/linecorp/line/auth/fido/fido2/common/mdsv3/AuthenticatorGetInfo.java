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

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class AuthenticatorGetInfo {
    private List<String> versions;
    private List<String> extensions;
    private String aaguid;
    private Map options;
    private Long maxMsgSize;

    private List<Long> pinUvAuthProtocols;
    private Long maxCredentialCountInList;
    private Long maxCredentialIdLength;
    private List<String> transports;
    private List<Map> algorithms;

    private Long maxSerializedLargeBlobArray;
    private Boolean forcePINChange;
    private Long minPINLength;
    private Long firmwareVersion;
    private Long maxCredBlobLength;

    private Long maxRPIDsForSetMinPINLength;
    private Long preferredPlatformUvAttempts;
    private Long uvModality;
    private Map certifications;
    private Long remainingDiscoverableCredentials;

    private List<Long> vendorPrototypeConfigCommands;
}
