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

package com.linecorp.line.auth.fido.fido2.server.repository;

import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import com.linecorp.line.auth.fido.fido2.server.model.Session;

@Repository
public class SessionRepositoryImp implements SessionRepository {
    private static final String KEY = "FIDO2::Session";
    private final RedisTemplate<String, Object> redisTemplate;
    private ValueOperations valueOperations;

    @Value("${fido.fido2.session-ttl-millis}")
    private long sessionTtlMillis;

    @Autowired
    public SessionRepositoryImp(RedisTemplate<String, Object> redisTemplate){
        this.redisTemplate = redisTemplate;
    }

    @PostConstruct
    private void init(){
        valueOperations = redisTemplate.opsForValue();
    }

    @Override
    public Session getSession(String id) {
        return (Session) valueOperations.get(makeKey(id));
    }

    private static String makeKey(String id) {
        return KEY + ":" + id;
    }

    @Override
    public void save(Session session) {
        valueOperations.set(makeKey(session.getId()), session, sessionTtlMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public void update(Session session) {
        Long timeToLive = redisTemplate.getExpire(makeKey(session.getId()));
        if (timeToLive == null) {
            timeToLive = sessionTtlMillis;
        }
        valueOperations.set(makeKey(session.getId()), session, timeToLive, TimeUnit.MILLISECONDS);
    }
}
