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

val lombokVersion = "1.18.18"

subprojects {
    apply(plugin = "java")
    apply(plugin = "maven-publish")

    configure<JavaPluginExtension> {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    group = "com.linecorp.line.auth.fido.fido2"
    version = "1.0.0-SNAPSHOT"

    extra["lombokVersion"] = lombokVersion
    extra["getMavenPublishUrl"] = { findProperty("publish.maven.url")?.toString() }
    extra["getMavenPublishUsername"] = { findProperty("publish.maven.username")?.toString() }
    extra["getMavenPublishPassword"] = { findProperty("publish.maven.password")?.toString() }

    repositories {
        mavenCentral()
        maven {
            url = uri("https://plugins.gradle.org/m2/")
        }
        google()
    }

    dependencies {
        "compileOnly"("org.projectlombok:lombok:$lombokVersion")
        "annotationProcessor"("org.projectlombok:lombok:$lombokVersion")

        "testImplementation"("org.mockito:mockito-core:5.23.0")
        // mockito-core depends on byte-buddy. Override spring boot's dependency version in test.
        "testImplementation"("net.bytebuddy:byte-buddy:1.17.7")
        "testImplementation"("net.bytebuddy:byte-buddy-agent:1.17.7")
    }
}
