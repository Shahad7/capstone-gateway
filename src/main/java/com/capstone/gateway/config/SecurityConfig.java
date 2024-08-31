package com.capstone.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.capstone.gateway.filter.JwtFilter;
import com.capstone.gateway.service.JwtUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
//    @Autowired
//    JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Autowired
    JwtFilter jwtFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
            .cors((c)->c.disable())
            .csrf((c)->c.disable())
            .authorizeHttpRequests((request)->request
            .requestMatchers(
                    "/api/v1/users/test",
                    "/api/v1/users/login",
                    "/api/v1/users/validate",
                    "/api/v1/users/signup",
                    "/api/v1/calculate/**")
            .permitAll()
            .anyRequest()
            .authenticated())  
            .exceptionHandling((e)->e.authenticationEntryPoint(jwtAuthenticationEntryPoint))
            .sessionManagement((session)->session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }



}
