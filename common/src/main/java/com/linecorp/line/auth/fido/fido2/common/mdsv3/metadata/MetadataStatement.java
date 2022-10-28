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
    private int authenticatorVersion;
    private String protocolFamily;
    private int schema;
    private List<Version> upv;

    private List<String> authenticationAlgorithms;
    private List<String> publicKeyAlgAndEncodings;
    private List<String> attestationTypes;
    private List<List<VerificationMethodDescriptor>> userVerificationDetails;
    private List<String> keyProtection;

    private boolean isKeyRestricted;
    private boolean isFreshUserVerificationRequired;
    private List<String> matcherProtection;
    private int cryptoStrength;
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
