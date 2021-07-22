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

package com.linecorp.line.auth.fido.fido2.springboot.autoconfigure.config;

import com.linecorp.line.auth.fido.fido2.server.repository.*;
import com.linecorp.line.auth.fido.fido2.server.service.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.redis.core.RedisTemplate;

@Configuration
@EnableJpaRepositories(basePackages = {"com.linecorp.line.auth.fido.fido2.server.repository"})
@EntityScan(basePackages = {"com.linecorp.line.auth.fido.fido2.server.entity"})
@ComponentScan(basePackages = {"com.linecorp.line.auth.fido.fido2.server.config","com.linecorp.line.auth.fido.fido2.server.service"})
@ConditionalOnClass(ChallengeService.class)
public class ChallengeServiceAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SessionRepository sessionRepository(RedisTemplate<String, Object> redisTemplate) {
        return new SessionRepositoryImp(redisTemplate);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionService sessionService(SessionRepository sessionRepository) {
        return new SessionServiceImpl(sessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public ChallengeService challengeService(final RpService rpService,
                                             final UserKeyService userKeyService,
                                             final SessionService sessionService) {
        return new ChallengeServiceImpl(rpService,
                userKeyService,
                sessionService);
    }
}
