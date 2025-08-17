package com.motavieirafelipe.authorization.domain.dto;

import com.motavieirafelipe.authorization.domain.enums.UserRole;
import com.motavieirafelipe.authorization.domain.interfaces.IAuthorities;

public record UserDto(
    String id,
    String login,
    String password,
    UserRole role
) implements IAuthorities { }