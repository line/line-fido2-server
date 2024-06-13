FROM eclipse-temurin:8-jdk
WORKDIR /workspace/app
COPY . .
RUN ./rpserver/gradlew bootJar
RUN ./server/gradlew dockerBuild