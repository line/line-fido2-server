/*
 * Copyright 2026 LY Corporation
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

import org.springframework.boot.gradle.tasks.bundling.BootJar

plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
    `java-library`
}

tasks.jar {
    enabled = true
}

tasks.named<BootJar>("bootJar") {
    enabled = false
}

tasks.processResources {
    exclude("**/*.sql")
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")

    api(project(":fido2-core"))
    api(project(":common"))

    //bouncy castle
    implementation("org.bouncycastle:bcprov-jdk15on:1.60")

    //eddsa library
    implementation("net.i2p.crypto:eddsa:0.3.0")

    //jwt
    implementation("com.auth0:java-jwt:3.4.0")

    //retrofit
    implementation("com.squareup.retrofit2:retrofit:2.4.0")
    implementation("com.squareup.retrofit2:converter-jackson:2.4.0")
}
