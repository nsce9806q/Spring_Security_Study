package com.csbuild.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.csbuild.security.config.auth.PrincipalDetails;
import com.csbuild.security.model.User;
import com.csbuild.security.repository.UserRepository;

@Controller // View를 리턴한다
public class IndexController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;


    // 로그인한 유저의 데이터를 가지고 오는 두가지 방법
    @GetMapping("/test/login")
    public @ResponseBody String testLogin(
        Authentication authentication,
        @AuthenticationPrincipal UserDetails userDetails){ // 의존성 주입
        System.out.println("/test/login============");
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        System.out.println("authentication: "+principalDetails.getUser());
        System.out.println("userDetails: "+userDetails.getUsername());
        return "세션정보 확인하기";
    }

    // OAuth의 경우
    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(
        Authentication authentication,
        @AuthenticationPrincipal OAuth2User oauth){
        System.out.println("/test/login============");
        OAuth2User oAuth2User = (OAuth2User)authentication.getPrincipal();
        System.out.println("authentication: "+oAuth2User.getAttributes());
        System.out.println("authentication: "+oauth.getAttributes());
        return "세션정보 확인하기";
    }


    @GetMapping({"","/"})
    public String index() {
        // 머스테치 기본폴더 src/main/resorces
        // 뷰리솔버 설정: templates
        return "index";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        System.out.println(user);
        
        // 권한 설정
        user.setRole("ROLE_USER");

        // 비밀번호 암호화
        String rawPassword = user.getPassword();
        String encodePassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encodePassword);
        
        // 나머지 저장
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @GetMapping("/joinProc")
    public @ResponseBody String joinProc() {
        return "회원가입 완료";
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    // 메소드 호출 전에 권한으로 막는다.
    // PostAuthorize는 메소드 종료 후 막는다.
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터";
    }
}
