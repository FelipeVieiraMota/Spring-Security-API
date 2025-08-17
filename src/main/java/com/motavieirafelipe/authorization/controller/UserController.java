package com.motavieirafelipe.authorization.controller;

import com.motavieirafelipe.authorization.domain.dto.FetchUserDto;
import com.motavieirafelipe.authorization.domain.dto.RegisterDto;
import com.motavieirafelipe.authorization.domain.dto.UserDto;
import com.motavieirafelipe.authorization.service.AuthorizationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final AuthorizationService authorizationService;

    @GetMapping("/ping")
    public String pong(){
        return "Pong " + UUID.randomUUID();
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserDto> register(@RequestBody @Valid RegisterDto data){
        return ResponseEntity.ok().body(authorizationService.register(data));
    }

    @DeleteMapping("{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUserById(@PathVariable String id){
        authorizationService.deleteUserById(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<FetchUserDto>> getAllUsers (
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return ResponseEntity.ok(authorizationService.getAllUsers(page, size));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<FetchUserDto> findUserById(@PathVariable String id){
        return ResponseEntity.ok().body(authorizationService.findUserById(id));
    }
}
