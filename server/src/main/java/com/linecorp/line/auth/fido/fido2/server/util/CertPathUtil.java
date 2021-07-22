/*
 * Copyright 2021 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.line.auth.fido.fido2.server.util;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.List;
import java.util.Set;

public class CertPathUtil {
    public static boolean validate(List<Certificate> certificateList, Set<TrustAnchor> trustAnchors, boolean revocationEnabled)
            throws GeneralSecurityException {
        CertPath certPath = CertificateUtil.generateCertPath(certificateList);
        return validate(certPath, trustAnchors, revocationEnabled);
    }

    public static boolean validate(CertPath certPath, Set<TrustAnchor> trustAnchors, boolean revocationEnabled)
            throws GeneralSecurityException {
        // set PKIX parameter
        PKIXParameters pkixParameters = new PKIXParameters(trustAnchors);
        pkixParameters.setRevocationEnabled(revocationEnabled);
        // certificate path validation
        CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
        try {
            certPathValidator.validate(certPath, pkixParameters);
            return true;
        } catch (CertPathValidatorException e) {
            return false;
        }
    }
}
