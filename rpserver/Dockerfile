FROM openjdk:8-jdk-alpine
EXPOSE 8080
COPY --from=build-image:latest /workspace/app/rpserver/build/libs/rpserver-*.jar rpserver.jar
ENTRYPOINT ["java","-jar","-Dspring.profiles.active=docker","/rpserver.jar"]
