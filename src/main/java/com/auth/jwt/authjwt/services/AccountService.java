package com.auth.jwt.authjwt.services;

import com.auth.jwt.authjwt.model.AppRole;
import com.auth.jwt.authjwt.model.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser user);
    AppRole addNewRole(AppRole role);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
