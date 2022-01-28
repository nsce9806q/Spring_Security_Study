package com.csbuild.security.config.oauth;

import com.csbuild.security.config.auth.PrincipalDetails;
import com.csbuild.security.model.User;
import com.csbuild.security.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
    
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    // Oauth 로그인 후 후처리 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("AccessToken"+ userRequest.getAccessToken());
        System.out.println("clientRegistration"+ userRequest.getClientRegistration());
        System.out.println("getAttributes"+ super.loadUser(userRequest).getAttributes());
        // 구글 로그인 -> code를 리턴 (Oauth 라이브러리) -> Access 토큰 요청
        // userrequest 정보 -> loadUser함수 호출하여 회원 프로필 받기

        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // 
        String provider = userRequest.getClientRegistration().getClientId();
        String providerId = oauth2User.getAttribute("sub");
        String username = provider+"_"+providerId; // ex) google_000000001
        String password = bCryptPasswordEncoder.encode("뭘적죠");; // 순환참조오류 발생
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(username);

        // user 검색했을때 user가 안나오면 회원가입
        if(userEntity == null){
            userEntity = User.builder()
                .username(username)
                .password(password)
                .email(email)
                .role(role)
                .provider(provider)
                .providerId(providerId)
                .build();

            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oauth2User.getAttributes()); 
    }
}
