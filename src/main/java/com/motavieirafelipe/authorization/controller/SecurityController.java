package com.motavieirafelipe.authorization.controller;

import com.motavieirafelipe.authorization.domain.dto.AuthenticationDto;
import com.motavieirafelipe.authorization.domain.dto.LoginResponseDto;
import com.motavieirafelipe.authorization.domain.dto.TokenDto;
import com.motavieirafelipe.authorization.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/v1/authorization")
@RequiredArgsConstructor
public class SecurityController {

    private final AuthenticationService authenticationService;

    @GetMapping("/ping")
    public String pong() {
        return "Pong " + UUID.randomUUID();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody @Valid AuthenticationDto data){
        return ResponseEntity.ok(new LoginResponseDto(authenticationService.login(data)));
    }

    @PostMapping("/token-validation")
    public ResponseEntity<Boolean> tokenValidation(@RequestBody TokenDto data) {

        if(authenticationService.validateToken(data)) {
            return ResponseEntity.ok(true);
        }

        return ResponseEntity.ok(false);
    }
}
