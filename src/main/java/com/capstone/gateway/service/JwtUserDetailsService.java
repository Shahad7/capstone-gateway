package com.capstone.gateway.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class JwtUserDetailsService implements UserDetailsService {
	
	@Autowired
	RestTemplate template;
	@Autowired
	Environment env;
   
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    	String url = env.getProperty("routes.user-service")+"/"+username;
        HashMap<String,Object> user = template.getForEntity(url,HashMap.class).getBody();
        if(user==null||!user.containsKey("username"))
            throw new UsernameNotFoundException(username);
        String extractedUsername = user.get("username").toString();
        String extractedPassword = user.get("password").toString();
        Collection<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("ROLE_USER"));
        User userDetails = new User(extractedUsername,extractedPassword,roles);
        return userDetails;
        
    }
}