FROM eclipse-temurin:8-jre
EXPOSE 8081
COPY --from=build-image:latest /workspace/app/server/build/libs/server-*.jar server.jar
CMD ["java","-jar","/server.jar"]