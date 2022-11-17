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
    private Integer maxMsgSize;

    private List<Integer> pinUvAuthProtocols;
    private Integer maxCredentialCountInList;
    private Integer maxCredentialIdLength;
    private List<String> transports;
    private List<Map> algorithms;

    private Integer maxAuthenticatorConfigLength;
    private Integer defaultCredProtect;
    private Integer firmwareVersion;
}
