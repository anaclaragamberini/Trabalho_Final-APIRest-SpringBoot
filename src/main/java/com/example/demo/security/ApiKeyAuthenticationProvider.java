package com.example.demo.security;

import com.example.demo.security.util.HashUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class ApiKeyAuthenticationProvider implements AuthenticationProvider {

    private final ApiKeyRepository apiKeyRepository;

    @Value("${security.api-key.salt}")
    private String salt;

    public ApiKeyAuthenticationProvider(ApiKeyRepository apiKeyRepository) {
        this.apiKeyRepository = apiKeyRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String apiKey = (String) authentication.getPrincipal();

        String keyHash = HashUtils.sha256Hex(apiKey + salt);

        return apiKeyRepository.findByKeyHashAndActiveTrue(keyHash)
                .<Authentication>map(entity -> {
                    ApiKeyAuthentication auth = new ApiKeyAuthentication(apiKey);
                    auth.setAuthenticated(true);
                    return auth;
                })
                .orElseThrow(() -> new InvalidApiKeyException("Invalid API Key"));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthentication.class.isAssignableFrom(authentication);
    }

    public static class InvalidApiKeyException extends AuthenticationException {
        public InvalidApiKeyException(String msg) {
            super(msg);
        }
    }
}