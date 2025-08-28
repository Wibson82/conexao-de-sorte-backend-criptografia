# ============================================================================
# 🐳 DOCKERFILE MULTI-ESTÁGIO - MICROSERVIÇO CRIPTOGRAFIA
# ============================================================================
# Padrão alinhado ao microserviço de Resultados (multi-stage, non-root, healthcheck).
#
# Build: docker build -t ghcr.io/<owner>/conexao-sorte-criptografia:latest .
# Run:   docker run -p 8088:8088 ghcr.io/<owner>/conexao-sorte-criptografia:latest
# ============================================================================

# === ESTÁGIO 1: BUILD ===
FROM maven:3.9.11-eclipse-temurin-24-alpine AS builder

LABEL maintainer="Conexão de Sorte <tech@conexaodesorte.com>"
WORKDIR /build

COPY pom.xml .
COPY .mvn/ .mvn/
COPY mvnw .
RUN --mount=type=cache,target=/root/.m2 mvn dependency:go-offline -B || true

COPY src/ src/
RUN --mount=type=cache,target=/root/.m2 mvn clean package -DskipTests -B

# === ESTÁGIO 2: RUNTIME ===
FROM eclipse-temurin:24-jre-alpine AS runtime
RUN apk add --no-cache tzdata curl dumb-init && rm -rf /var/cache/apk/*
ENV TZ=America/Sao_Paulo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN addgroup -g 1001 -S appgroup \
 && adduser -u 1001 -S appuser -G appgroup
WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /build/target/*.jar app.jar

# Porta padrão do serviço Criptografia
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8088/actuator/health || exit 1

USER appuser:appgroup
LABEL org.opencontainers.image.title="Conexão de Sorte - Criptografia"
LABEL org.opencontainers.image.description="Microserviço de Criptografia"
ENTRYPOINT ["dumb-init", "--", "java"]
CMD ["-jar", "app.jar"]

