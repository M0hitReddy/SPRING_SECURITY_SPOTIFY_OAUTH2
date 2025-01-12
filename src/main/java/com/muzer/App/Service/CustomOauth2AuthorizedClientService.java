package com.muzer.App.Service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;

import java.util.HashMap;
import java.util.Map;

public class CustomOauth2AuthorizedClientService implements OAuth2AuthorizedClientService {
    final Map<String, OAuth2AuthorizedClient> authorizedClients = new HashMap<>();

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        String key = generateKey(clientRegistrationId, principalName);
        System.out.println("loadAuthorizedClient :::: "+authorizedClients.get(key));
        return (T) authorizedClients.get(key);
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        String key = generateKey(authorizedClient.getClientRegistration().getRegistrationId(), principal.getName());
        authorizedClients.put(key, authorizedClient);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        String key = generateKey(clientRegistrationId, principalName);
        authorizedClients.remove(key);
    }

    private String generateKey(String clientRegistrationId, String principalName) {
        return String.format("oauth2:client:%s:%s", clientRegistrationId, principalName);
    }
}
