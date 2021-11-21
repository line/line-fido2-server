FROM openjdk:8-jdk-slim as build-rp
WORKDIR /workspace/rp
COPY . .
RUN ./rpserver/gradlew bootJar

FROM openjdk:8-jdk-slim
EXPOSE 8080
COPY --from=build-rp /workspace/rp/rpserver/build/libs/rpserver-*.jar rpserver.jar
ENV spring.profiles.active=docker
ENTRYPOINT ["java","-jar","-Dspring.profiles.active=docker","/rpserver.jar"]
