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

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import com.linecorp.line.auth.fido.fido2.common.mdsv3.AuthenticatorGetInfo;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.protocol.Version;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class MetadataStatement {
    private String legalHeader;
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private String description;

    private Map<String, String> alternativeDescriptions;
    private Integer authenticatorVersion;
    private String protocolFamily;
    private Integer schema;
    private List<Version> upv;

    private List<String> authenticationAlgorithms;
    private List<String> publicKeyAlgAndEncodings;
    private List<String> attestationTypes;
    private List<List<VerificationMethodDescriptor>> userVerificationDetails;
    private List<String> keyProtection;

    private Boolean isKeyRestricted;
    private Boolean isFreshUserVerificationRequired;
    private List<String> matcherProtection;
    private Integer cryptoStrength;
    private List<String> attachmentHint;

    private List<String> tcDisplay;
    private String tcDisplayContentType;
    private List<DisplayPNGCharacteristicsDescriptor> tcDisplayPNGCharacteristics;
    private List<String> attestationRootCertificates;
    private List<EcdaaTrustAnchor> ecdaaTrustAnchors;

    private String icon;
    private List<ExtensionDescriptor> supportedExtensions;
    private AuthenticatorGetInfo authenticatorGetInfo;
}
