package com.motavieirafelipe.authorization.domain.interfaces;

import com.motavieirafelipe.authorization.domain.enums.UserRole;
import com.motavieirafelipe.authorization.exception.ForbiddenException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

import static com.motavieirafelipe.authorization.domain.enums.UserRole.ADMIN;

public interface IAuthorities {

    default Collection<? extends GrantedAuthority> authorities(UserRole role) {

        if(role == ADMIN) {
            return List.of(
                    new SimpleGrantedAuthority("ROLE_ADMIN")//,
                    //new SimpleGrantedAuthority("ROLE_COMPANY")
            );
        }

//        if(role == COMPANY) {
//            return List.of(
//                    new SimpleGrantedAuthority("ROLE_COMPANY")
//            );
//        }

        throw new ForbiddenException("Not Allowed.");
    }
}