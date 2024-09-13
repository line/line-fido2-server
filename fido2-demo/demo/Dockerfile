FROM gradle:6.8.3-jdk11 AS builder
ENV OPEN_SOURCE_BUILD=true

USER root
WORKDIR /workspace/app
COPY . .
RUN ./fido2-demo/demo/gradlew dockerBuild

FROM openjdk:11-jre-slim-buster
EXPOSE 8081
COPY --from=builder /workspace/app/fido2-demo/demo/build/libs/demo*.jar demo.jar
ENTRYPOINT ["java","-jar","/demo.jar"]
