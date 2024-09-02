package com.capstone.gateway.filter;
import java.io.IOException;
import java.util.HashMap;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.capstone.gateway.service.JwtUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {
    //This is the jwt filter added in JwtConfig, through which all requests pass
    //it extracts the jwt token and verifies it and then allows access to the route


    @Autowired
    JwtUserDetailsService jwtUserDetailsService;
    @Autowired
    RestTemplate template;
    
    private static final Logger LOGGER = Logger.getLogger(ALREADY_FILTERED_SUFFIX);
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, java.io.IOException {
        String bearerToken = request.getHeader("Authorization");
        String username = null;
        String token = null;

        if(bearerToken!=null&&bearerToken.startsWith("Bearer")){
            token = bearerToken.substring(7);

        try{
            String url = "http://localhost:5001/api/v1/users/validate";
            HashMap<String,String> jwtToken = new HashMap<>();
            jwtToken.put("token",token);
            ResponseEntity responseObj = template.postForEntity(url,jwtToken, HashMap.class);
            if(responseObj.getStatusCodeValue()==200){
                username = ((HashMap<String,String>) responseObj.getBody()).get("username");
                UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);
                if(username!=null&& SecurityContextHolder.getContext().getAuthentication()==null){
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }

            }

        }
        catch (Exception e){
	             response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	             response.getWriter().write("Invalid token: " + e.getMessage());
        		LOGGER.info("Invalid token : "+e.getMessage());
    
            }
        }

        filterChain.doFilter(request,response);
    }
}
