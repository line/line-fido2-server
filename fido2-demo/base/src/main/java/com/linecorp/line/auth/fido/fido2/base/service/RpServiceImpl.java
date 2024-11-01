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

package com.linecorp.line.auth.fido.fido2.base.service;

import com.linecorp.line.auth.fido.fido2.base.repository.RpRepository;
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRpEntity;
import com.linecorp.line.auth.fido.fido2.base.entity.RpEntity;
import com.linecorp.line.auth.fido.fido2.server.service.RpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class RpServiceImpl implements RpService {
    private final RpRepository rpRepository;

    @Autowired
    public RpServiceImpl(RpRepository rpRepository) {
        this.rpRepository = rpRepository;
    }

    @Override
    public boolean contains(String rpId) {
        return rpRepository.findById(rpId).isPresent();
    }

    @Override
    public PublicKeyCredentialRpEntity get(String rpId) {
        Optional<RpEntity> optionalRp = rpRepository.findById(rpId);
        if (optionalRp.isPresent()) {
            return convert(optionalRp.get());
        }
        return null;
    }

    @Override
    public List<PublicKeyCredentialRpEntity> getAll() {
        List<PublicKeyCredentialRpEntity> rps = new ArrayList<>();
        rpRepository.findAll().forEach(e -> rps.add(convert(e)));
        return rps;
    }

    private PublicKeyCredentialRpEntity convert(RpEntity rpEntity) {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity();
        rp.setId(rpEntity.getId());
        rp.setIcon(rpEntity.getIcon());
        rp.setName(rpEntity.getName());

        return rp;
    }
}
