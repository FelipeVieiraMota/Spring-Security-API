package com.motavieirafelipe.authorization.infra;

import com.motavieirafelipe.authorization.domain.dto.ErrorResponseDto;
import com.motavieirafelipe.authorization.exception.ForbiddenException;
import com.motavieirafelipe.authorization.service.JWTTokenService;
import com.motavieirafelipe.authorization.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class SecurityFilter extends OncePerRequestFilter {

    private static final String APPLICATION_JSON = "application/json";
    private final JWTTokenService tokenService;
    private final UserService service;

    @Value("${api.security.token.secret}")
    private String secret;

    /*
     * This validation is different from the others because in this case we are
     * reaching also database instead only to check JWT.
     * */

    @Override
    protected void doFilterInternal(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final FilterChain filterChain
    ) throws IOException {

        try
        {
            var token = tokenService.recoverToken(request);

            if(token != null) {

                final var login = tokenService.tokenSubject(secret, token);
                final var user = service.findByLogin(login);
                final var claims = tokenService.extractClaims(secret, token);

                if (user == null || user.getAuthorities() == null) {
                    throw new ForbiddenException("Not Allowed.");
                }

                if (tokenService.isTokenExpired(claims)) {
                    throw new ForbiddenException("Not Allowed.");
                }

                final var authentication = new UsernamePasswordAuthenticationToken(
                        user,
                        null,
                        user.getAuthorities()
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);
        }
        catch (ForbiddenException exception)
        {
            exception.printStackTrace();
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(APPLICATION_JSON);
            response.getWriter().write(new ErrorResponseDto(LocalDateTime.now(), HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.name() , exception.getMessage()).toString());
        }
        catch (Throwable exception)
        {
            exception.printStackTrace();
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType(APPLICATION_JSON);
            response.getWriter().write(new ErrorResponseDto(LocalDateTime.now(), HttpStatus.FORBIDDEN.value(), "Unpredictable error happened." , exception.getMessage()).toString());
        }
    }
}
