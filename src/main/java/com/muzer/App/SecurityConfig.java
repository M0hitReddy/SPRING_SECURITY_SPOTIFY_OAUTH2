package com.muzer.App;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.muzer.App.AuthenticationSpotify.SpotifyAuthProvider;
import com.muzer.App.Config.CustomOAuth2SuccessHandler;
import com.muzer.App.Filters.AddAuthHeaderFilter;
import com.muzer.App.Repository.RedisSessionRepository;
import com.muzer.App.Service.CustomOAuth2UserService;
import com.muzer.App.Service.CustomOauth2AuthorizedClientService;
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
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig  {

//    @Value("${spring.security.oauth2.client.registration.spotify.client-id}")
//    private String spotifyClientId;
//    @Value("${spring.security.oauth2.client.registration.spotify.client-secret}")
//    private String spotifyClientSecret;
//    @Value("${spring.security.oauth2.client.registration.google.client-id}")
//    private String googleClientId;
//    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
//    private String googleClientSecret;

//    @Autowired
//    public RedisTemplate<String, Object> redisTemplate;

//    @Bean
//    public OAuth2AuthorizedClientService authorizedClientService() {
//        return new CustomOauth2AuthorizedClientService();
//    }
    private final OAuth2AuthorizedClientService authorizedClientService;
    @Autowired public CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
//        this.customOAuth2UserService = customOAuth2UserService;
    }




    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedOrigins(List.of("http://localhost:5173"));
                    corsConfiguration.setAllowedMethods(List.of("GET", "POST"));
                    corsConfiguration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
                    return corsConfiguration;
                }))
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/oauth2/**", "/login/**", "/logout/**").permitAll()
                                .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())
                .addFilterBefore(new AddAuthHeaderFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")))
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2Login -> oauth2Login
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService)
                        )
                        .authorizedClientService(authorizedClientService)
                        .successHandler(new CustomOAuth2SuccessHandler(authorizedClientService))

                );
        return http.build();
    }
//    @Bean
//    public JwtDecoder jwtDecoder() {
//
//        return JwtDecoders.fromIssuerLocation("https://accounts.spotify.com");
//    }

    @Bean
    public JwtDecoder jwtDecoder() {

        return JwtDecoders.fromIssuerLocation("https://accounts.google.com");
    }

    @Bean
    public JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {
        final JwtDecoder decoder = jwtDecoder();
        return new JwtDecoderFactory<ClientRegistration>() {
            @Override
            public JwtDecoder createDecoder(ClientRegistration context) {
                return decoder;
            }
        };

    }

//    private JwtAuthenticationConverter jwtAuthenticationConverter() {
//        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
//        grantedAuthoritiesConverter.setAuthoritiesClaimName("scope");
//
//        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
//        return jwtAuthenticationConverter;
//    }

//    @Bean
//    public ClientRegistrationRepository spotifyClientRegistrationRepository() {
//        return new InMemoryClientRegistrationRepository(spotifyClientRegistration(), googleClientRegistration());
//    }

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

//    private ClientRegistration spotifyClientRegistration() {
//        return ClientRegistration.withRegistrationId("spotify")
//                .clientId(spotifyClientId)
//                .clientSecret(spotifyClientSecret)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("http://localhost:8080/login/oauth2/code/spotify")
//                .scope("user-read-email")
//                .authorizationUri("https://accounts.spotify.com/authorize")
//                .tokenUri("https://accounts.spotify.com/api/token")
//                .userInfoUri("https://api.spotify.com/v1/me")
//                .userNameAttributeName("id")
//                .clientName("Spotify")
//                .build();
//    }
//
//    private ClientRegistration googleClientRegistration() {
//        return ClientRegistration.withRegistrationId("google")
//                .clientId(googleClientId)
//                .clientSecret(googleClientSecret)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .redirectUri("http://localhost:8080/login/oauth2/code/google")
//                .scope("openid", "profile", "email")
//                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//                .tokenUri("https://oauth2.googleapis.com/token")
//                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
//                .userNameAttributeName("sub")
//                .clientName("Google")
//                .build();
//    }


    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new SpotifyAuthProvider();
    }


}