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
    private int maxMsgSize;

    private List<Integer> pinUvAuthProtocols;
    private int maxCredentialCountInList;
    private int maxCredentialIdLength;
    private List<String> transports;
    private List<Map> algorithms;

    private int maxAuthenticatorConfigLength;
    private int defaultCredProtect;
    private int firmwareVersion;
}
