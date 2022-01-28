package com.csbuild.security.config.auth;

import com.csbuild.security.model.User;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.Data;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;;

// 시큐리티가 로그인 주소 요청이오면 낚아채서 로그인을 진행한다
// 로그인을 진행이 완료가 되면 시큐리티 세션을 만든다
// 객체타입 => Authentication 객체
// 객체안에 User정보가 있다.
// User 객체 타입은 UserDetails 타입 객체

// Security Session => Authentication => UserDetail 순으로 접근 가능

@Data
// userDetails OauthUser 두개의 타입이 있으므로, PrinciplaDetails로 묶어서 사용하면
// 구분지을 필요 없이 객체를 꺼내 쓸 수 있다.
public class PrincipalDetails implements UserDetails, OAuth2User{

    private User user;
	private Map<String, Object> attributes;

    public PrincipalDetails(User user){
        this.user = user;
    }

	public PrincipalDetails(User user, Map<String, Object> attributes){
        this.user = user;
		this.attributes = attributes; 
    }

    @Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
	
    // 해당 유저의 권한을 리턴하는 부분
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();
		collet.add(()->{ return user.getRole();});
		return collet;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return null;
	}
}
