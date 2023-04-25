package com.tb.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@EnableWebSecurity
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .mvcMatchers("/products/**").access("hasAuthority('SCOPE_products.read')")
//                .anyRequest().authenticated()
//                .and()
//                .oauth2ResourceServer()
//                .jwt();
//        return http.build();
        http.authorizeRequests(authorizeRequests ->
                        authorizeRequests.antMatchers("/api/**").authenticated().anyRequest().permitAll()

                )

                .oauth2ResourceServer()

                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        System.out.println(1);
                    }
                })
                .jwt();
        // @formatter:on

        return http.build();
    }
}