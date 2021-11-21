FROM openjdk:8-jdk-slim
EXPOSE 8081
COPY --from=build-image:latest /workspace/app/server/build/libs/server-*.jar server.jar
ENTRYPOINT ["java","-jar","/server.jar"]