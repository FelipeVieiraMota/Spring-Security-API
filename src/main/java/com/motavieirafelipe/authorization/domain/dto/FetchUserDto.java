package com.motavieirafelipe.authorization.domain.dto;

import com.motavieirafelipe.authorization.domain.enums.UserRole;
import com.motavieirafelipe.authorization.domain.interfaces.IAuthorities;

public record FetchUserDto(
    String id,
    String login,
    UserRole role
) implements IAuthorities { }