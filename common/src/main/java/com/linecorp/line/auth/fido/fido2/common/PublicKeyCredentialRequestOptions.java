package com.linecorp.line.auth.fido.fido2.common;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientInputs;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialDescriptor;

import lombok.Data;

@Data
@JsonInclude(Include.NON_NULL)
public class PublicKeyCredentialRequestOptions {
    private String challenge;
    private long timeout;
    private String rpId;
    @JsonInclude(Include.NON_NULL)
    private List<ServerPublicKeyCredentialDescriptor> allowCredentials;
    @JsonInclude(Include.NON_NULL)
    private UserVerificationRequirement userVerification;
    //extensions
    private AuthenticationExtensionsClientInputs extensions;
}
