package com.auth.jwt.authjwt;

import com.auth.jwt.authjwt.model.AppRole;
import com.auth.jwt.authjwt.model.AppUser;
import com.auth.jwt.authjwt.services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class AuthJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    CommandLineRunner start(AccountService accountService)
    {
        return args -> {
            accountService.addNewRole(new AppRole(null,"USER"));
            accountService.addNewRole(new AppRole(null,"ADMIN"));
            accountService.addNewRole(new AppRole(null,"CUSTOMER_MANAGER"));
            accountService.addNewRole(new AppRole(null,"PRODUCT_MANAGER"));
            accountService.addNewRole(new AppRole(null,"BILLS_MANAGER"));

            accountService.addNewUser(new AppUser(null,"user1", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user2", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user3", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"user4", "1234", new ArrayList<>()));
            accountService.addNewUser(new AppUser(null,"admin", "1234", new ArrayList<>()));

            accountService.addRoleToUser("user1","BILLS_MANAGER");
            accountService.addRoleToUser("user1","USER");
            accountService.addRoleToUser("user2","PRODUCT_MANAGER");
            accountService.addRoleToUser("user2","USER");
            accountService.addRoleToUser("user3","CUSTOMER_MANAGER");
            accountService.addRoleToUser("user3","USER");
            accountService.addRoleToUser("user4","USER");
            accountService.addRoleToUser("admin","ADMIN");
        };
    }

}
