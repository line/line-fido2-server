package com.linecorp.line.auth.fido.fido2.common;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientInputs;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialDescriptor;
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialUserEntity;

import lombok.Data;

@Data
@JsonInclude(Include.NON_NULL)
public class PublicKeyCredentialCreationOptions {
    private PublicKeyCredentialRpEntity rp;
    private ServerPublicKeyCredentialUserEntity user;
    private String challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams;
    private long timeout;
    private List<ServerPublicKeyCredentialDescriptor> excludeCredentials;
    @JsonInclude(Include.NON_NULL)
    private AuthenticatorSelectionCriteria authenticatorSelection;
    @JsonInclude(Include.NON_NULL)
    private AttestationConveyancePreference attestation;
    //extensions
    private AuthenticationExtensionsClientInputs extensions;
}
