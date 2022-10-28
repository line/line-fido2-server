/*
 * Copyright (c) 2018 LINE Corporation. All rights reserved.
 * LINE Corporation PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */

package com.linecorp.line.auth.fido.fido2.common.mdsv3;

import lombok.Data;

@Data
public class StatusReport {
    private AuthenticatorStatus status;
    private String effectiveDate;
    private String certificate;
    private String url;
    private String certificationDescriptor;
    private String certificateNumber;
    private String certificationPolicyVersion;
    private String certificationRequirementsVersion;
}
