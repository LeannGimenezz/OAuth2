package com.project.securityservice;

import com.project.securityservice.config.RsaKeysConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeysConfig.class)
public class SpringOAuth2Application {

    public static void main(String[] args) {
        SpringApplication.run(SpringOAuth2Application.class, args);
    }

}
