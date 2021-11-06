FROM openjdk:8-jdk-slim
EXPOSE 8080
ADD build/libs/rpserver-*.jar rpserver.jar
ENTRYPOINT ["java","-jar","/rpserver.jar"]
