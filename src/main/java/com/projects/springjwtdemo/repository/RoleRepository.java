package com.projects.springjwtdemo.repository;

import com.projects.springjwtdemo.entity.Role;
import com.projects.springjwtdemo.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
