FROM eclipse-temurin:8-jre
EXPOSE 8080
COPY --from=build-image:latest /workspace/app/rpserver/build/libs/rpserver-*.jar rpserver.jar
CMD ["java","-Dspring.profiles.active=docker","-jar","/rpserver.jar"]