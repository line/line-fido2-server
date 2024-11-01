/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
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

package com.linecorp.line.auth.fido.fido2.base.config;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.security.Security;

@Configuration
public class SecurityConfiguration {
    @PostConstruct
    private void setEnableCRLDP() {
        System.setProperty("com.sun.security.enableCRLDP", "true");
    }

    @PostConstruct
    private void setBouncyCastleSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @PostConstruct
    private void setEdDSASecurityProvider() {
        Security.addProvider(new EdDSASecurityProvider());
    }
}
