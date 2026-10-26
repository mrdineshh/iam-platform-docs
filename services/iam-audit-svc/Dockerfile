FROM gradle:9.7.1-jdk21 AS build
WORKDIR /workspace
COPY iam-audit-svc/ iam-audit-svc/
COPY iam-service-kit/ iam-service-kit/
WORKDIR /workspace/iam-audit-svc
RUN --mount=type=cache,target=/root/.gradle gradle bootJar --no-daemon

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/iam-audit-svc/build/libs/*.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-Duser.timezone=UTC", "-jar", "app.jar"]
