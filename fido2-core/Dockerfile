FROM gradle:6.8.3-jdk11 AS builder
ENV OPEN_SOURCE_BUILD=true

USER root
WORKDIR /workspace/app
COPY . .
RUN ./server/gradlew dockerBuild

FROM openjdk:11-jre-slim-buster
EXPOSE 8081
COPY --from=builder /workspace/app/server/build/libs/server*.jar server.jar

ENTRYPOINT ["java","-jar","-Dspring.profiles.active=local","/server.jar"]
