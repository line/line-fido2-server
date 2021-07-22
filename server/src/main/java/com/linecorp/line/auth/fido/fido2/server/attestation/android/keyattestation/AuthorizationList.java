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

package com.linecorp.line.auth.fido.fido2.server.attestation.android.keyattestation;

import java.util.List;

import lombok.Data;

@Data
public class AuthorizationList {
//    purpose  [1] EXPLICIT SET OF INTEGER OPTIONAL,
//    algorithm  [2] EXPLICIT INTEGER OPTIONAL,
//    keySize  [3] EXPLICIT INTEGER OPTIONAL,
//    digest  [5] EXPLICIT SET OF INTEGER OPTIONAL,
//    padding  [6] EXPLICIT SET OF INTEGER OPTIONAL,
//    ecCurve  [10] EXPLICIT INTEGER OPTIONAL,
//    rsaPublicExponent  [200] EXPLICIT INTEGER OPTIONAL,
//    activeDateTime  [400] EXPLICIT INTEGER OPTIONAL,
//    originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
//    usageExpireDateTime  [402] EXPLICIT INTEGER OPTIONAL,
//    noAuthRequired  [503] EXPLICIT NULL OPTIONAL,
//    userAuthType  [504] EXPLICIT INTEGER OPTIONAL,
//    authTimeout  [505] EXPLICIT INTEGER OPTIONAL,
//    allowWhileOnBody  [506] EXPLICIT NULL OPTIONAL,
//    allApplications  [600] EXPLICIT NULL OPTIONAL,
//    applicationId  [601] EXPLICIT OCTET_STRING OPTIONAL,
//    creationDateTime  [701] EXPLICIT INTEGER OPTIONAL,
//    origin  [702] EXPLICIT INTEGER OPTIONAL,
//    rollbackResistant  [703] EXPLICIT NULL OPTIONAL,
//    rootOfTrust  [704] EXPLICIT RootOfTrust OPTIONAL,
//    osVersion  [705] EXPLICIT INTEGER OPTIONAL,
//    osPatchLevel  [706] EXPLICIT INTEGER OPTIONAL,
//    attestationChallenge  [708] EXPLICIT INTEGER OPTIONAL,
//    attestationApplicationId  [709] EXPLICIT OCTET_STRING OPTIONAL,

    private List<Integer> purpose;
    private Integer algorithm;
    private Integer keySize;
    private List<Integer> digest;
    private List<Integer> padding;
    private Integer ecCurve;
    private Integer rsaPublicExponent;
    private Integer activeDateTime;
    private Integer originationExpireDateTime;
    private Integer usageExpireDateTime;
    private boolean noAuthRequired;
    private Integer userAuthType;
    private Integer authTimeout;
    private boolean allowWhileOnBody;
    private boolean allApplications;
    private byte[] applicationId;
    private Integer creationDateTime;
    private Integer origin;
    private boolean rollbackResistant;
    private RootOfTrust rootOfTrust;
    private Integer osVersion;
    private Integer osPatchLevel;
    private Integer attestationChallenge;
    private byte[] attestationApplicationId;
}
