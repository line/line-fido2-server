# Builder
FROM gradle:6.8.3-jdk8 AS builder

COPY . /home/gradle/project

WORKDIR /home/gradle/project/server

RUN gradle -Dorg.gradle.daemon=false dockerBuild --stacktrace --info

# Application
FROM openjdk:8-jdk-slim

COPY --from=builder /home/gradle/project/server/build/libs/server-*.jar  /opt/app/server.jar

WORKDIR /opt/app

RUN rm -rf /var/cache/*

EXPOSE 8080

ENTRYPOINT ["java","-jar","server.jar"]