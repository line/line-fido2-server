FROM openjdk:8-jdk-alpine
WORKDIR /workspace/app
COPY . .
RUN ./rpserver/gradlew bootJar
RUN ./server/gradlew dockerBuild