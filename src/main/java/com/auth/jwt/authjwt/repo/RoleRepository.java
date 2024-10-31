package com.auth.jwt.authjwt.repo;

import com.auth.jwt.authjwt.model.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<AppRole, Long> {
    AppRole findByName(String name);
}
