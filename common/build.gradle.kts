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

tasks.test {
    useJUnitPlatform()
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
    implementation("com.fasterxml.jackson.core:jackson-databind:2.9.6")
    implementation("com.fasterxml.jackson.core:jackson-core:2.9.6")
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.9.6")
    // The spring-boot-starter-validation on server module and the version it depends on must match
    implementation("org.hibernate.validator:hibernate-validator:6.2.0.Final")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
    testImplementation("org.assertj:assertj-core:3.21.0")

    // For Bean validation test
    implementation("javax.el:javax.el-api:3.0.0")
    implementation("org.glassfish:javax.el:3.0.0")
}
