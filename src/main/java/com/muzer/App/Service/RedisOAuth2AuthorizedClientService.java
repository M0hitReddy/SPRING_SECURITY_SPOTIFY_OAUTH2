package com.muzer.App.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Service
public class RedisOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
    private final RedisTemplate<String, Object> redisTemplate;

    @Autowired
    public RedisOAuth2AuthorizedClientService(RedisTemplate<String, Object> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        String key = generateKey(authorizedClient.getClientRegistration().getRegistrationId(), principal.getName());

        Map<String, Object> data = new HashMap<>();
        data.put("clientRegistration", serializeClientRegistration(authorizedClient.getClientRegistration()));
        data.put("principalName", principal.getName());
        data.put("accessToken", serializeAccessToken(authorizedClient.getAccessToken()));
        if (authorizedClient.getRefreshToken() != null) {
            data.put("refreshToken", serializeRefreshToken(authorizedClient.getRefreshToken()));
        }

        redisTemplate.opsForValue().set(key, data);
    }

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        String key = generateKey(clientRegistrationId, principalName);
        Object value = redisTemplate.opsForValue().get(key);

        if (value instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) value;

            // Extract and reconstruct objects as shown earlier
            ClientRegistration clientRegistration = reconstructClientRegistration((Map<String, Object>) data.get("clientRegistration"));
            OAuth2AccessToken accessToken = reconstructAccessToken((Map<String, Object>) data.get("accessToken"));
            OAuth2RefreshToken refreshToken = reconstructRefreshToken((Map<String, Object>) data.get("refreshToken"));

            return (T) new OAuth2AuthorizedClient(clientRegistration, principalName, accessToken, refreshToken);
        }

        return null;
    }

    private ClientRegistration reconstructClientRegistration(Map<String, Object> map) {
        return ClientRegistration
                .withRegistrationId((String) map.get("registrationId"))
                .clientId((String) map.get("clientId"))
                .clientSecret((String) map.get("clientSecret"))
                .authorizationGrantType(new AuthorizationGrantType((String) map.get("authorizationGrantType")))
                .redirectUri((String) map.get("redirectUri"))
                .scope((Collection<String>) map.get("scopes"))
                .authorizationUri((String) map.get("authorizationUri"))
                .tokenUri((String) map.get("tokenUri"))
                .userInfoUri((String) map.get("userInfoEndpoint"))
                .build();
    }

    private OAuth2AccessToken reconstructAccessToken(Map<String, Object> map) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                (String) map.get("tokenValue"),
                Instant.ofEpochMilli((Long) map.get("issuedAt")),
                Instant.ofEpochMilli((Long) map.get("expiresAt"))
        );
    }

    private OAuth2RefreshToken reconstructRefreshToken(Map<String, Object> map) {
        return new OAuth2RefreshToken(
                (String) map.get("tokenValue"),
                Instant.ofEpochMilli((Long) map.get("issuedAt"))
        );
    }


    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        String key = generateKey(clientRegistrationId, principalName);
        redisTemplate.delete(key);
    }

    private String generateKey(String clientRegistrationId, String principalName) {
        return String.format("oauth2:client:%s:%s", clientRegistrationId, principalName);
    }

    private Map<String, Object> serializeClientRegistration(ClientRegistration clientRegistration) {
        Map<String, Object> map = new HashMap<>();
        map.put("registrationId", clientRegistration.getRegistrationId());
        map.put("clientId", clientRegistration.getClientId());
        map.put("clientSecret", clientRegistration.getClientSecret());
        map.put("authorizationGrantType", clientRegistration.getAuthorizationGrantType().getValue());
        map.put("redirectUri", clientRegistration.getRedirectUri());
        map.put("scopes", clientRegistration.getScopes());
        map.put("authorizationUri", clientRegistration.getProviderDetails().getAuthorizationUri());
        map.put("tokenUri", clientRegistration.getProviderDetails().getTokenUri());
        map.put("userInfoEndpoint", clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
        return map;
    }

    private Map<String, Object> serializeAccessToken(OAuth2AccessToken accessToken) {
        Map<String, Object> map = new HashMap<>();
        map.put("tokenValue", accessToken.getTokenValue());
        map.put("issuedAt", accessToken.getIssuedAt().toEpochMilli());
        map.put("expiresAt", accessToken.getExpiresAt().toEpochMilli());
        return map;
    }

    private Map<String, Object> serializeRefreshToken(OAuth2RefreshToken refreshToken) {
        Map<String, Object> map = new HashMap<>();
        map.put("tokenValue", refreshToken.getTokenValue());
        map.put("issuedAt", refreshToken.getIssuedAt().toEpochMilli());
        return map;
    }
}