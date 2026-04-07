package com.linecorp.line.auth.fido.fido2.common;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
public enum CredentialMediationRequirement {
    SILENT("silent"),
    OPTIONAL("optional"),
    CONDITIONAL("conditional"),
    REQUIRED("required"),
    ;

    @JsonValue
    @Getter
    private final String value;

    @JsonCreator(mode=JsonCreator.Mode.DELEGATING)
    public static CredentialMediationRequirement fromValue(String value) {
        return Arrays.stream(values())
                     .filter(e -> e.value.equals(value))
                     .findFirst()
                     .get();
    }
}
