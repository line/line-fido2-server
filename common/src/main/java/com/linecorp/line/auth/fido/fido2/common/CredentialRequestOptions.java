package com.linecorp.line.auth.fido.fido2.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Data;

@Data
@JsonInclude(Include.NON_NULL)
public class CredentialRequestOptions {
    CredentialMediationRequirement mediation;
    PublicKeyCredentialRequestOptions publicKey;
}
