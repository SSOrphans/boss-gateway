FROM openjdk
COPY ./boss-gateway-controller/target/boss-gateway-controller-0.0.1-SNAPSHOT.jar /app/
CMD java -jar /app/boss-gateway-controller-0.0.1-SNAPSHOT.jar