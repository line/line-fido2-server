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

package com.linecorp.line.auth.fido.fido2.server.entity;

import com.linecorp.line.auth.fido.fido2.common.server.AttestationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "USER_KEY")
public class UserKeyEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;    // internal

    @ManyToOne
    private RpEntity rpEntity;

    @Column(nullable = false, length = 128)
    private String userId;

    @Column(nullable = false, length = 64)
    private String username;

    @Column(nullable = false, length = 64)
    private String userDisplayName;

    @Column(length = 128)
    private String userIcon;

    @Column(nullable = false, length = 36)
    private String aaguid;

    @Column(nullable = false, length = 256)
    private String credentialId;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String publicKey;

    @Column(nullable = false)
    private int signatureAlgorithm;

    @Column
    Long signCounter;

    @Column
    private AttestationType attestationType;

    @OneToMany(cascade = CascadeType.ALL,
            fetch = FetchType.LAZY,
            mappedBy = "userKeyEntity")
    private List<AuthenticatorTransportEntity> transports = new ArrayList<>();

    @Column
    private Boolean rk;

    @Column
    private Integer credProtect;

    @Temporal(TemporalType.TIMESTAMP)
    @Column
    private Date registeredTimestamp;

    @Temporal(TemporalType.TIMESTAMP)
    @Column
    private Date authenticatedTimestamp;

}
