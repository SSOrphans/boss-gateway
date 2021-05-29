FROM openjdk
COPY ./boss-gateway/target/boss-gateway-0.0.1-SNAPSHOT.jar /app/
CMD java -jar /app/boss-gateway-0.0.1-SNAPSHOT.jar