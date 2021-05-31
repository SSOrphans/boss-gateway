package org.ssor.boss.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableEurekaClient
@SpringBootApplication
@ComponentScan("org.ssor.boss")
@EntityScan("org.ssor.boss.core.entity")
@EnableJpaRepositories("org.ssor.boss.core.repository")
public class BossGatewayControllerApplication
{

  public static void main(String[] args)
  {
    SpringApplication.run(BossGatewayControllerApplication.class, args);
  }

}
