package com.motavieirafelipe.authorization.infra;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfiguration implements WebMvcConfigurer {

    private final SecurityFilter securityFilter;

    private static final String   PATH_PATTERN     = "/**";
    private static final String   ALLOWED_HEADERS  = "*";
    private static final String   ONLY_LOCAL_HOST  = "http://localhost:*";
    private static final String[] ALLOWED_METHODS  = { "GET", "POST", "PUT", "DELETE", "OPTIONS" };
    private static final String   ERROR_PATH       = "/error";
    private static final String   H2_CONSOLE       = "/h2-console/**";
    private static final String   ACTUATOR         = "/actuator/**";
    private static final String   LOGIN            = "/v1/authorization/login";
    private static final String   TOKEN_VALIDATION = "/v1/authorization/token-validation";
    private static final String   PING             = "/v1/authorization/ping";

    // http://localhost:[port]/v1/authorization/swagger-ui/index.html
    private static final String[] SWAGGER_WHITELIST = {
        "/v1/authorization/api-docs/**",
        "/v1/authorization/swagger-ui/**",
        "/v1/authorization/swagger-ui.html"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity httpSecurity) throws Exception {

        return  httpSecurity
            .csrf(AbstractHttpConfigurer::disable)
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(getAuthorizationManagerRequestMatcherRegistryCustomizer())
            .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    private Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
        getAuthorizationManagerRequestMatcherRegistryCustomizer() {
        return authorize ->
                authorize
                .requestMatchers(SWAGGER_WHITELIST)      .permitAll()
                .requestMatchers(ERROR_PATH)    .permitAll()
                .requestMatchers(H2_CONSOLE)             .permitAll()
                .requestMatchers(GET, ACTUATOR)          .permitAll()
                .requestMatchers(POST, LOGIN)            .permitAll()
                .requestMatchers(POST, TOKEN_VALIDATION) .permitAll()
                .requestMatchers(GET, PING)              .permitAll()
                .requestMatchers(OPTIONS, "/**").permitAll()
                .anyRequest().authenticated();
    }

    @Bean
    public AuthenticationManager authenticationManager(
        final AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Override
    public void addCorsMappings(final CorsRegistry registry) {
        registry
            .addMapping(PATH_PATTERN)
            .allowedOriginPatterns(ONLY_LOCAL_HOST)
            .allowedMethods(ALLOWED_METHODS)
            .allowedHeaders(ALLOWED_HEADERS)
            .allowCredentials(true);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
