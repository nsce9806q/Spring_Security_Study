package com.csbuild.security.repository;

import com.csbuild.security.model.User;

import org.springframework.data.jpa.repository.JpaRepository;

// jpaRepository를 통해 CRUD 함수를 사용가능
public interface UserRepository extends JpaRepository<User, Integer>{
    // findBy 규칙 -> Username문법
    // select * from user where username = 
    public User findByUsername(String username); // JPA query method

    // select * from user where email = 
    public User findByEmail(String email);
}
