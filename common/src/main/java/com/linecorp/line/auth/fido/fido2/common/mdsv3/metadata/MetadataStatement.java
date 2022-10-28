package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import com.linecorp.line.auth.fido.fido2.common.mdsv3.AuthenticatorGetInfo;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata.*;
import com.linecorp.line.auth.fido.fido2.common.mdsv3.protocol.Version;
import lombok.Data;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

//    DOMString legalHeader;
//            AAID aaid;
//            AAGUID aaguid;
//            DOMString[]attestationCertificateKeyIdentifiers;
//            required DOMString description;
//            AlternativeDescriptions alternativeDescriptions;
//
//            required unsigned long authenticatorVersion;
//            required DOMString protocolFamily;
//            required unsigned short schema;
//            required Version[]upv;
//            required DOMString[]authenticationAlgorithms;
//
//            required DOMString[]publicKeyAlgAndEncodings;
//            required DOMString[]attestationTypes;
//            required VerificationMethodANDCombinations[]userVerificationDetails;
//            required DOMString[]keyProtection;
//            boolean isKeyRestricted;
//
//            boolean isFreshUserVerificationRequired;
//            required DOMString[]matcherProtection;
//            unsigned short cryptoStrength;
//            DOMString[]attachmentHint;
//            required DOMString[]tcDisplay;
//
//            DOMString tcDisplayContentType;
//            DisplayPNGCharacteristicsDescriptor[]tcDisplayPNGCharacteristics;
//            required DOMString[]attestationRootCertificates;
//            EcdaaTrustAnchor[]ecdaaTrustAnchors;
//            DOMString icon;
//
//            ExtensionDescriptor[]supportedExtensions;
//            AuthenticatorGetInfo authenticatorGetInfo;

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
