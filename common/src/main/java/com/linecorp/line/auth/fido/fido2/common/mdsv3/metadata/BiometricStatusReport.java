package com.linecorp.line.auth.fido.fido2.common.mdsv3.metadata;

import lombok.Data;

@Data
public class BiometricStatusReport {
    Integer certLevel;
    String  modality;
    String  effectiveDate;
    String  certificationDescriptor;
    String  certificateNumber;
    String  certificationPolicyVersion;
    String  certificationRequirementsVersion;
}
