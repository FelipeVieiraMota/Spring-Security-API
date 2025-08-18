
FROM maven:3.9.9-eclipse-temurin-17 AS build

# Install curl
RUN apt-get update && apt-get install -y curl

# Verify curl installation
RUN curl --version

COPY ./src /app/src
COPY ./pom.xml /app
WORKDIR /app
RUN mvn clean package -DskipTests


FROM eclipse-temurin:17-jre
RUN groupadd --system spring && useradd --system --gid spring --create-home spring
USER spring:spring
COPY --from=build /app/target/*.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]