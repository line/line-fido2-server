FROM openjdk:8-jdk-slim
EXPOSE 8081
ADD build/libs/server-*.jar server.jar
ENTRYPOINT ["java","-jar","/server.jar"]
