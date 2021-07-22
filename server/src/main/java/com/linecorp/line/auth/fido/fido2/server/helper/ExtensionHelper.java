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

package com.linecorp.line.auth.fido.fido2.server.helper;

import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientOutputs;
import com.linecorp.line.auth.fido.fido2.server.model.AuthenticatorExtension;
import com.linecorp.line.auth.fido.fido2.server.model.UserKey;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExtensionHelper {
    public static UserKey createUserKeyWithExtensions(UserKey.UserKeyBuilder userKeyBuilder, AuthenticationExtensionsClientOutputs clientExtensions, AuthenticatorExtension authenticatorExtensions) {
        // verify extension
        log.info("Verify extension");

        // check authenticator extensions
        log.info("Check authenticator extension");

        if (authenticatorExtensions != null) {
            log.debug("Extensions: {}", authenticatorExtensions);
            if (authenticatorExtensions.getCredProtect() != null) {
                log.info("Handle credProtect extension");
                userKeyBuilder.credProtect(authenticatorExtensions.getCredProtect().getValue());
            }
        }

        // check client extensions
        log.info("Check client extension");
        if (clientExtensions != null) {
            log.info("Client extension output: {}", clientExtensions);
            if (clientExtensions.getCredProps() != null) {
                userKeyBuilder.rk(clientExtensions.getCredProps().getRk());
            }
        }

        return userKeyBuilder.build();
    }
}
