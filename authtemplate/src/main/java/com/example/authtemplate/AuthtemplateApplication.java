package com.example.authtemplate;

import com.example.authtemplate.role.Role;
import com.example.authtemplate.role.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class AuthtemplateApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthtemplateApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(RoleRepository roleRepository) {
		return args -> {
			if(roleRepository.findByName("USER").isEmpty())
				roleRepository.save(Role.builder().name("USER").build());
		};
	}

}

