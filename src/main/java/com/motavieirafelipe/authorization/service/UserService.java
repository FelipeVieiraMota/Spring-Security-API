package com.motavieirafelipe.authorization.service;

import com.motavieirafelipe.authorization.domain.entity.User;
import com.motavieirafelipe.authorization.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor

public class UserService {

    private final IUserRepository repository;

    public UserDetails findByLogin(String username) {
        return repository.findByLogin(username);
    }

    public User save(User newUser) {
        return repository.save(newUser);
    }

    public void deleteUserById(String id) {
        repository.deleteById(id);
    }

    public Page<User> getAllUsers(int page, int size) {
        return repository.findAll(PageRequest.of(page, size));
    }

    public User findUserById(final String id) {
        return repository.findUserById(id);
    }
}
