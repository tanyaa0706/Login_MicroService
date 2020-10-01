package com.cg.springjwt.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cg.springjwt.security.services.UserDetailsServiceImpl;

public class AuthTokenFilter extends OncePerRequestFilter {
	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			System.out.println("API PATH : "+ request.getRequestURL().toString());
			String jwt = parseJwt(request);
			if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
				// extract user information
				String username = jwtUtils.getUserNameFromJwtToken(jwt);

				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				// create AuthenticationToken
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				System.out.println("User Authority : "+userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				//SecurityContextHolder is the most fundamental object where we store details
				//of the present security context of the application (includes details of the principal).
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}

		filterChain.doFilter(request, response);
	}

	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");

		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7, headerAuth.length());
		}

		return null;
	}
}
