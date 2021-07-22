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

package com.linecorp.line.auth.fido.fido2.server.service;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.linecorp.line.auth.fido.fido2.server.error.InternalErrorCode;
import com.linecorp.line.auth.fido.fido2.server.exception.FIDO2ServerRuntimeException;
import com.linecorp.line.auth.fido.fido2.server.model.Session;
import com.linecorp.line.auth.fido.fido2.server.repository.SessionRepository;
import com.linecorp.line.auth.fido.fido2.server.util.HmacUtil;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class SessionServiceImpl implements SessionService {
    private final SessionRepository sessionRepository;

    @Autowired
    public SessionServiceImpl(SessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    public Session createSessionData() {
        Session session = new Session();
        String sessionId = UUID.randomUUID().toString();
        SecretKey hmacKey;
        try {
            hmacKey = HmacUtil.generateHmacKey();
        } catch (NoSuchAlgorithmException e) {
            throw new FIDO2ServerRuntimeException(InternalErrorCode.CRYPTO_OPERATION_EXCEPTION,
                                                  "Exception during generating hmac key", e);
        }
        String hmacKeyString = Base64.getUrlEncoder().withoutPadding().encodeToString(hmacKey.getEncoded());
        session.setId(sessionId);
        session.setHmacKey(hmacKeyString);
        return session;
    }

    @Override
    public void createSession(Session session) {
        sessionRepository.save(session);
    }

    @Override
    public Session getSession(String sessionId) {
        return sessionRepository.getSession(sessionId);
    }

    @Override
    public void revokeSession(String sessionId) {
        //TODO: TTL NOT WORK
//        Session session = sessionRepository.getSession(sessionId);
//        if (session != null) {
//            session.setServed(true);
//            sessionRepository.update(session);
//        } else {
//            log.warn("no such session with session id: {}", sessionId);
//        }
    }
}
