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

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.linecorp.line.auth.fido.fido2.server.entity.UserKeyEntity;

import java.util.List;

@Repository
public interface UserKeyRepository extends CrudRepository<UserKeyEntity, Long> {
    List<UserKeyEntity> findAllByRpEntityIdAndUserId(String rpId, String userId);
    UserKeyEntity findByRpEntityIdAndCredentialId(String rpId, String credentialId);
}
