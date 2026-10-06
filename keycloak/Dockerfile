# -----------------------------------------------------------------------------
# Keycloak + custom role mapper (multi-stage build, everything inside Docker).
#
# Stage 1 builds the Java SPI mapper JAR with Maven (no host Java/Maven needed).
# Stage 2 bakes the JAR into the Keycloak image via `kc.sh build`.
# -----------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY mapper/pom.xml ./pom.xml
RUN echo "=== [1/2] Resolving Maven dependencies (a lot is downloaded on the first build) ===" && mvn dependency:go-offline
COPY mapper/src ./src
RUN echo "=== [2/2] Building the mapper JAR ===" && mvn -DskipTests package

FROM quay.io/keycloak/keycloak:26.0.8
COPY --from=build /app/target/role-mapper.jar /opt/keycloak/providers/
RUN echo "=== [3/3] Rebuilding Keycloak optimized image with the mapper ===" && /opt/keycloak/bin/kc.sh build
