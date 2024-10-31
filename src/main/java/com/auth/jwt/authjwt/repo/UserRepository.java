package com.auth.jwt.authjwt.repo;

import com.auth.jwt.authjwt.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;



public interface UserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}