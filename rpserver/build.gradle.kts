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
    application
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

tasks.jar {
    enabled = true
}

tasks.test {
    useJUnitPlatform()
}

tasks.register("dockerBuild") {
    doFirst {
        tasks.jar.get().enabled = System.getenv("OPEN_SOURCE_BUILD") != "true"
    }
    dependsOn(tasks.named<BootJar>("bootJar"))
}

dependencies {
    implementation(project(":common"))

    implementation("org.springframework.boot:spring-boot-starter-web")

    //thymeleaf
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")

    //springdoc
    implementation("org.springdoc:springdoc-openapi-ui:1.6.15")

    implementation("javax.activation:activation:1.1.1")
    implementation("org.springframework.boot:spring-boot-devtools")
    compileOnly("org.springframework.boot:spring-boot-configuration-processor")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
