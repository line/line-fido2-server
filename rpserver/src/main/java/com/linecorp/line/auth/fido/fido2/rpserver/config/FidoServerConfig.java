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

package com.linecorp.line.auth.fido.fido2.rpserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@ConfigurationProperties(prefix = "fido2-server")
@Data
public class FidoServerConfig {
    private String scheme;
    private String host;
    private String port;
    private final Endpoint endpoint = new Endpoint();

    @Data
    public static class Endpoint {
        private String getRegChallenge;
        private String sendRegResponse;
        private String getAuthChallenge;
        private String sendAuthResponse;
        private String getDeleteCredentials;
        private String getU2fRegChallenge;
        private String sendU2fRegResponse;
        private String getU2fAuthChallenge;
        private String sendU2fAuthResponse;
        private String getDeleteU2fCredentials;
        private String getU2fTrustedFacets;
    }
}
