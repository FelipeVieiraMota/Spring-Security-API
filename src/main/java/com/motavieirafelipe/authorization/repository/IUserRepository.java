package com.motavieirafelipe.authorization.repository;

import com.motavieirafelipe.authorization.domain.entity.User;
import com.motavieirafelipe.authorization.domain.enums.UserRole;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

@Repository
public interface IUserRepository extends JpaRepository<User, String> {

    UserDetails findByLogin(String login);

    User findUserById(String id);

    Page<User> findByRoleNot(UserRole role, Pageable pageable);

    Page<User> findByRole(UserRole roles, Pageable pageable);
}