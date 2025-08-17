package com.motavieirafelipe.authorization.domain.mappers;

import com.motavieirafelipe.authorization.domain.dto.UserDto;
import com.motavieirafelipe.authorization.domain.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface IUserMapper {
    UserDto toDto(User entity);
}
