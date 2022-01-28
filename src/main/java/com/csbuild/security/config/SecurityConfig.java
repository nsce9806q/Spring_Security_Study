package com.csbuild.security.config;

import com.csbuild.security.config.oauth.PrincipalOauth2UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 된다
// secuered 어노테이션 활성화
// preAuthorize/postAuthorize 어노테이션 활성화
// 인덱스 컨트롤러에서 간단히 사용가능
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    @Autowired
    private PrincipalOauth2UserService PrincipalOauth2UserService;
    
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
        .antMatchers("/user/**").authenticated() // 로그인한 사람만 들어올수 있고
        .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") //해당 권한이 있어야 접속할 수 있는 경로
        .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll() // 나머지 경로는 모두 허용
        .and()
            .formLogin()
            .loginPage("/loginForm") // 권한없는 페이지로 들어가면 로그인 페이지로 들어감
            .loginProcessingUrl("/login") //login 주소가 호출되면 시큐리티가 대신 로그인 진행
            .defaultSuccessUrl("/") // 로그인 성공이 되면, 기존 접속하려했던 경로로 리다이렉트
        .and()
            .oauth2Login()
            .loginPage("/loginForm")
            .userInfoEndpoint()
            .userService(PrincipalOauth2UserService); // Oauth로그인 이후 후처리
    }
}

// oauth 로그인 순서
// 코드받기 (인증)
// 엑세스 토큰 (권한)
// 사용자프로필 정보를 가져오고
// 그 정보로 회원가입으로 바로 시키거나, 정보를 추가적으로 받아서 회원가입을 시킨다