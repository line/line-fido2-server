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

import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialParameters;
import lombok.Data;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

@Data
public class AuthenticatorGetInfo {
    private List<String> versions;
    private List<String> extensions;
    private String aaguid;
    private Map options;
    private BigInteger maxMsgSize;

    private List<Long> pinUvAuthProtocols;
    private BigInteger maxCredentialCountInList;
    private BigInteger maxCredentialIdLength;
    private List<String> transports;
    private List<PublicKeyCredentialParameters> algorithms;

    private BigInteger maxSerializedLargeBlobArray;
    private Boolean forcePINChange;
    private BigInteger minPINLength;
    private BigInteger firmwareVersion;
    private BigInteger maxCredBlobLength;

    private BigInteger maxRPIDsForSetMinPINLength;
    private BigInteger preferredPlatformUvAttempts;
    private BigInteger uvModality;
    private Map certifications;
    private BigInteger remainingDiscoverableCredentials;

    private List<BigInteger> vendorPrototypeConfigCommands;
}
