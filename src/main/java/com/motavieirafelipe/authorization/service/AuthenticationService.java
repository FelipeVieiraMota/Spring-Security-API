package com.motavieirafelipe.authorization.service;

import com.motavieirafelipe.authorization.domain.dto.AuthenticationDto;
import com.motavieirafelipe.authorization.domain.dto.TokenDto;
import com.motavieirafelipe.authorization.domain.entity.User;
import com.motavieirafelipe.authorization.domain.mappers.IUserMapper;
import com.motavieirafelipe.authorization.exception.ForbiddenException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JWTTokenService tokenService;
    private final IUserMapper mapper;

    @Value("${api.security.token.secret}")
    private String secret;

    public String login(AuthenticationDto data) {
        try {
            final var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
            final var authenticate = this.authenticationManager.authenticate(usernamePassword);
            final var dto = mapper.toDto((User) authenticate.getPrincipal());
            return tokenService.generateToken(secret, dto);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
            throw new ForbiddenException(throwable.getMessage());
        }
    }

    public boolean validateToken(final TokenDto data) {
        return tokenService.validateToken(secret, data.token());
    }
}
