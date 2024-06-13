FROM eclipse-temurin:8-jdk
WORKDIR /workspace/app
COPY . .
RUN --mount=type=cache,target=/root/.gradle \
	./rpserver/gradlew --no-daemon bootJar
RUN --mount=type=cache,target=/root/.gradle \
	./server/gradlew --no-daemon dockerBuild