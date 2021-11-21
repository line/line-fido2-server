FROM openjdk:8-jdk-slim as build-server
WORKDIR /workspace/fido2
COPY . .
RUN ./server/gradlew dockerBuild

FROM openjdk:8-jdk-slim
EXPOSE 8081
COPY --from=build-server /workspace/fido2/server/build/libs/server-*.jar server.jar
ENTRYPOINT ["java","-jar","/server.jar"]