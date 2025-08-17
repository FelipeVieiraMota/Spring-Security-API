package com.motavieirafelipe.authorization.domain.mappers;

import com.motavieirafelipe.authorization.domain.dto.FetchUserDto;
import com.motavieirafelipe.authorization.domain.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface IFetchMapper {
    FetchUserDto toDto(User entity);
}
