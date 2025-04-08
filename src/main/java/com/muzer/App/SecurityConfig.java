package com.muzer.App;

import com.muzer.App.Beans.CustomAuthenticationEntryPoint;
import com.muzer.App.Config.CustomOAuth2SuccessHandler;
import com.muzer.App.Filters.AddAuthHeaderFilter;
import com.muzer.App.Repository.UserRepository;
import com.muzer.App.Service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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
    private final CustomOAuth2UserService customOAuth2UserService;
    private final UserRepository userRepository;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public SecurityConfig(OAuth2AuthorizedClientService authorizedClientService,
                          CustomOAuth2UserService customOAuth2UserService,
                          UserRepository userRepository,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        this.authorizedClientService = authorizedClientService;
        this.customOAuth2UserService = customOAuth2UserService;
        this.userRepository = userRepository;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
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
                        sessionManagement.sessionCreationPolicy(authorizedClientService.))
                .oauth2Login(oauth2Login -> oauth2Login

                                .authorizedClientService(authorizedClientService)
                                .userInfoEndpoint(userInfo -> userInfo
                                        .userService(customOAuth2UserService)
                                )
//                        .authorizedClientService(authorizedClientService)
                                .successHandler(new CustomOAuth2SuccessHandler(authorizedClientService, userRepository))

                )
                .logout(logout -> logout
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(200);
                        })
                        .addLogoutHandler(new CookieClearingLogoutHandler("JSESSIONID", "token", "idToken"))
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
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


//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        return new SpotifyAuthProvider();
//    }


}