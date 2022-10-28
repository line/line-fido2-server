/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.DisplayPNGCharacteristicsDescriptor;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.ExtensionDescriptor;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.VerificationMethodDescriptor;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.protocol.Version;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class MetadataStatement_ {
    private String aaid;
    private String aaguid;
    private List<String> attestationCertificateKeyIdentifiers;
    private String description;
    private int authenticatorVersion;
    private String protocolFamily;
    private Version[] upv;
    private String assertionScheme;
    private int authenticationAlgorithm;
    private int publicKeyAlgAndEncoding;
    private List<Integer> attestationTypes;
    private VerificationMethodDescriptor[][] userVerificationDetails;
    private int keyProtection;
    private boolean isKeyRestricted;
    private boolean isFreshUserVerificationRequired;
    private int matcherProtection;
    private long attachmentHint;    //unsigned long
    private boolean isSecondFactorOnly;
    private int tcDisplay;
    private String tcDisplayContentType;
    private DisplayPNGCharacteristicsDescriptor[] tcDisplayPNGCharacteristics;
    private List<String> attestationRootCertificates;
    private EcdaaTrustAnchor[] ecdaaTrustAnchors;
    private String icon;
    private ExtensionDescriptor[] supportedExtensions;

    //v2
    private String legalHeader;
    private Map<String, String> alternativeDescriptions;
    private List<Integer> authenticationAlgorithms;
    private List<Integer> publicKeyAlgAndEncodings;
    private int cryptoStrength;
    private String operatingEnv;
}
