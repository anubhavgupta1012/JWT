package com.jwt.filter;

import com.jwt.service.CustomUserDetailsService;
import com.jwt.service.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;

@Configuration
public class JWTTokenFilter implements Filter {

    @Autowired
    private JWTService jwtService;
    @Autowired
    private CustomUserDetailsService userDetailsService;


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.contains("Bearer ")) {
            String token = authorization.split(" ")[1];
            String username = jwtService.getUserName(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                if (jwtService.validateToken(token, userDetailsService.loadUserByUsername(username))) {
                    UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, Arrays.asList(() -> "read"));
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
