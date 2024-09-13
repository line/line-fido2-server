FROM gradle:6.8.3-jdk11 AS builder
ENV OPEN_SOURCE_BUILD=true

USER root
WORKDIR /workspace/app
COPY . .
RUN ./rpserver/gradlew dockerBuild

FROM openjdk:11-jre-slim-buster
EXPOSE 8080
COPY --from=builder /workspace/app/rpserver/build/libs/rpserver*.jar rpserver.jar
ENTRYPOINT ["java","-jar","-Dspring.profiles.active=docker","/rpserver.jar"]
