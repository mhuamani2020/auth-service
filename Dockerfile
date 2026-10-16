# syntax=docker/dockerfile:1
# ============================================================================
# auth-service — imagen Docker (Parte II: "cada microservicio en un contenedor
# independiente"). Build multi-etapa:
#   1) compila el microservicio con Maven, instalando antes la librería
#      compartida bank-resilience-commons en el repositorio local;
#   2) copia el jar a una imagen JRE ligera.
#
# El contexto de build es la RAÍZ del proyecto (ver docker-compose.yml):
#   docker build -f auth-service/Dockerfile -t auth-service .
# ============================================================================
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /workspace

# 1) Librería compartida de resiliencia (no está publicada en un repositorio Maven)
COPY bank-resilience-commons/pom.xml bank-resilience-commons/pom.xml
COPY bank-resilience-commons/src bank-resilience-commons/src
RUN mvn -q -B -f bank-resilience-commons/pom.xml -DskipTests install

# 2) Microservicio
COPY auth-service/pom.xml auth-service/pom.xml
COPY auth-service/src auth-service/src
RUN mvn -q -B -f auth-service/pom.xml -DskipTests package

# ---------- Etapa de ejecución ----------
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY --from=build /workspace/auth-service/target/*.jar app.jar
EXPOSE 8084
HEALTHCHECK --interval=10s --timeout=5s --start-period=45s --retries=12 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8084'
ENTRYPOINT ["java","-jar","/app/app.jar"]
