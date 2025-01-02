package com.muzer.App;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.muzer.App.AuthenticationSpotify.SpotifyAuthProvider;
import com.muzer.App.Config.CustomOAuth2SuccessHandler;
import com.muzer.App.Repository.RedisSessionRepository;
import com.muzer.App.Service.RedisOAuth2AuthorizedClientService;
import jakarta.servlet.http.Cookie;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

    @Value("${spring.security.oauth2.client.registration.spotify.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.spotify.client-secret}")
    private String clientSecret;

    @Autowired
    public RedisTemplate<String, Object> redisTemplate;

//    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(RedisTemplate<String, Object> redisTemplate) {
        return new RedisOAuth2AuthorizedClientService(redisTemplate, new ObjectMapper());
    }
    private final OAuth2AuthorizedClientService authorizedClientService;

    public SecurityConfig(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(
                        Customizer.withDefaults()
                )
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/oauth2/**", "/login/**", "/logout/**").permitAll()
                                .anyRequest().authenticated()

                )
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())
//                .addFilterBefore(new AddAuthHeaderFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer
                                .jwt(jwt -> jwt
                                        .jwkSetUri("https://accounts.spotify.com/.well-known/jwks.json")
                                )
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2Login -> oauth2Login.authorizedClientService(authorizedClientService(redisTemplate)).successHandler(new CustomOAuth2SuccessHandler(authorizedClientService)));
//                .oauth2Login(Customizer.withDefaults())


//        http.addFilterAfter(tokenCookieFilter, OAuth2LoginAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {

        return JwtDecoders.fromIssuerLocation("https://accounts.spotify.com");
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("scope");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(spotifyClientRegistration());
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManager.class);
    }

//    @Bean
//    public BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter() {
//        BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter = new BearerTokenAuthenticationFilter();
//        bearerTokenAuthenticationFilter.setAuthenticationManager(authenticationManager());
//        return bearerTokenAuthenticationFilter;
//    }


//    @Value("${spring.security.oauth2.client.registration.spotify.client-id}")
//    private String clientId;
//    @Value("${spring.security.oauth2.client.registration.spotify.client-secret}")
//    private String clientSecret;

    private ClientRegistration spotifyClientRegistration() {

        return ClientRegistration.withRegistrationId("spotify")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/login/oauth2/code/spotify")
                .scope("user-read-email")
                .authorizationUri("https://accounts.spotify.com/authorize")
                .tokenUri("https://accounts.spotify.com/api/token")
                .userInfoUri("https://api.spotify.com/v1/me")
                .userNameAttributeName("id")
                .clientName("Spotify")
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new SpotifyAuthProvider();
    }


}