package com.motavieirafelipe.authorization.service;

import com.motavieirafelipe.authorization.domain.dto.FetchUserDto;
import com.motavieirafelipe.authorization.domain.dto.RegisterDto;
import com.motavieirafelipe.authorization.domain.dto.UserDto;
import com.motavieirafelipe.authorization.domain.entity.User;
import com.motavieirafelipe.authorization.domain.mappers.IFetchMapper;
import com.motavieirafelipe.authorization.domain.mappers.IUserMapper;
import com.motavieirafelipe.authorization.exception.UserAlreadyExistsException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
@RequiredArgsConstructor
public class AuthorizationService implements UserDetailsService {

    private final UserService service;
    private final IFetchMapper fetchMapper;
    private final IUserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return service.findByLogin(username);
    }

    public UserDto register(@RequestBody @Valid RegisterDto data) {

        final var user = service.findByLogin(data.login());

        if( user != null ) {
            throw new UserAlreadyExistsException();
        }

        final String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
        final User newUser = new User(data.login(), encryptedPassword, data.role());
        return userMapper.toDto(service.save(newUser));
    }

    public void deleteUserById(final String id) {
        service.deleteUserById(id);
    }

    public Page<FetchUserDto> getAllUsers(final int page, final int size) {
        return service.getAllUsers(page, size).map(fetchMapper::toDto);
    }

    public FetchUserDto findUserById(final String id) {
        return fetchMapper.toDto(service.findUserById(id));
    }
}