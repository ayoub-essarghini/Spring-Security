package com.auth.jwt.authjwt.services;

import com.auth.jwt.authjwt.model.AppRole;
import com.auth.jwt.authjwt.model.AppUser;
import com.auth.jwt.authjwt.repo.RoleRepository;
import com.auth.jwt.authjwt.repo.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    private final UserRepository _userRepository;
    private final RoleRepository _roleRepository;
    private final PasswordEncoder _passwordEncoder;

    public AccountServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        _userRepository = userRepository;
        _roleRepository = roleRepository;
        _passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser user) {
        String pwd = user.getPassword();
        user.setPassword(_passwordEncoder.encode(pwd));
        return _userRepository.save(user);
    }

    @Override
    public AppRole addNewRole(AppRole role) {
        return _roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser user = _userRepository.findByUsername(username);
        AppRole role = _roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return _userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return _userRepository.findAll();
    }
}
