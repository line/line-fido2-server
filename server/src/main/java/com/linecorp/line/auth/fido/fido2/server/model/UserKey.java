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

package com.linecorp.line.auth.fido.fido2.server.model;

import java.security.PublicKey;
import java.util.Date;
import java.util.List;

import com.linecorp.line.auth.fido.fido2.common.AuthenticatorTransport;
import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import com.linecorp.line.auth.fido.fido2.common.server.COSEAlgorithm;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserKey {
    // rp info
    private String rpId;
    // user info
    private String id;
    private String name;
    private String icon;
    private String displayName;
    // credential info
    private String aaguid;
    private String credentialId;
    private PublicKey publicKey;
    private COSEAlgorithm algorithm;
    private Long signCounter;
    private AttestationType attestationType;

    // transports
    private List<AuthenticatorTransport> transports;    // WebAuthn Level2

    // credProps - rk
    private Boolean rk; // WebAuthn Level2

    // credProtect
    private Integer credProtect;

    private Date registeredAt;
    private Date authenticatedAt;
}
