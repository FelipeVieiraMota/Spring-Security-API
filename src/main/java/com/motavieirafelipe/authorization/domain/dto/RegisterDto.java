package com.motavieirafelipe.authorization.domain.dto;

import com.motavieirafelipe.authorization.domain.enums.UserRole;

public record RegisterDto(String login, String password, UserRole role) { }