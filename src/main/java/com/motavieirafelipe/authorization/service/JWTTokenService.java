package com.motavieirafelipe.authorization.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.motavieirafelipe.authorization.domain.dto.UserDto;
import com.motavieirafelipe.authorization.exception.ForbiddenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JWTTokenService {
    private static final String APPLICATION_JSON = "application/json";

    /*
     * Use this method to validate JWT inside your API filter.
     * */
    public void checkTokenRoles(
            final String secret,
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain filterChain
    ) throws IOException {
        try {

            final var token = recoverToken(request);

            if (token != null) {

                final var claims = extractClaims(secret, token);

                if (isTokenExpired(claims)) {
                    throw new ForbiddenException("Not Allowed.");
                }

                final var roles = claims.get("roles", List.class);

                final List<SimpleGrantedAuthority> authorities = getAuthorities(roles);

                final var authentication = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(),
                        null,
                        authorities
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(APPLICATION_JSON);
            response.getWriter().write("{\"error\":\"Unauthorized access\"}");
        }
    }

    private static List<SimpleGrantedAuthority> getAuthorities(List<?> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.toString())).toList();
    }

    public Claims extractClaims(final String secret, final String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            e.printStackTrace();
            throw new RuntimeException("Token validation failed", e);
        }
    }

    public boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public String generateToken(final String secret, final UserDto user){
        try{
            final List<String> roles = getRoles(user);
            final Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.login())
                    .withClaim("roles", roles)
                    .withExpiresAt(genExpirationDate())
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    private static List<String> getRoles(final UserDto user) {
        final Collection<? extends GrantedAuthority> authorities = user.authorities(user.role());
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    public String tokenSubject(final String secret, final String token){
        try {
            return JWT.require(Algorithm.HMAC256(secret))
                    .withIssuer("auth-api")
                    .build()
                    .verify(token)
                    .getSubject();
        } catch (JWTVerificationException exception){
            return "";
        }
    }

    public boolean validateToken(final String secret, final String token) {
        try {
            JWT.require(Algorithm.HMAC256(secret))
                    .withIssuer("auth-api")
                    .build()
                    .verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    private Instant genExpirationDate()  {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }

    public String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
    }
}
