/*
 * Copyright 2024-2026 LY Corporation
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
    `java-library`
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    enabled = true
}

tasks.named<BootJar>("bootJar") {
    enabled = false
}

publishing {
    publications {
        create<MavenPublication>("mavenJar") {
            from(components["java"])
        }
    }

    repositories {
        maven {
            val getMavenPublishUrl = extra["getMavenPublishUrl"] as () -> String?
            val getMavenPublishUsername = extra["getMavenPublishUsername"] as () -> String?
            val getMavenPublishPassword = extra["getMavenPublishPassword"] as () -> String?

            url = uri(getMavenPublishUrl() ?: "")

            val mavenUsername = getMavenPublishUsername()
            if (mavenUsername != null) {
                credentials {
                    username = mavenUsername
                    password = getMavenPublishPassword()
                }
            }
        }
    }
}

dependencies {
    implementation(project(":common"))

    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor")

    implementation("org.springframework.boot:spring-boot-starter-logging")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-cache")

    //jwt
    implementation("com.auth0:java-jwt:3.4.0")

    //bouncy castle
    implementation("org.bouncycastle:bcprov-jdk15on:1.60")

    //eddsa library
    implementation("net.i2p.crypto:eddsa:0.3.0")

    //retrofit
    implementation("com.squareup.retrofit2:retrofit:2.4.0")
    implementation("com.squareup.retrofit2:converter-jackson:2.4.0")

    implementation("commons-codec:commons-codec:1.15")

    //cache
    implementation("com.github.ben-manes.caffeine:caffeine")

    // Test
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
}
