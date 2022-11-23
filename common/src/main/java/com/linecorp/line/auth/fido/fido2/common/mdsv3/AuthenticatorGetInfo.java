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
