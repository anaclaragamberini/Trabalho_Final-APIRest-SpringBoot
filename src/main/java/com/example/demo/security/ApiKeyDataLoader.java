package com.example.demo.security;

import com.example.demo.security.util.HashUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApiKeyDataLoader {

    @Value("${security.api-key.salt}")
    private String salt;

    @Bean
    public CommandLineRunner loadApiKeys(ApiKeyRepository apiKeyRepository) {
        return args -> {

            if (apiKeyRepository.count() == 0) {

                String rawKey = "sk-123456";

                String keyHash = HashUtils.sha256Hex(rawKey + salt);

                apiKeyRepository.save(new ApiKey(keyHash, "Chave de Teste"));

                System.out.println("API KEY DE TESTE: " + rawKey);
            }

        };
    }
}