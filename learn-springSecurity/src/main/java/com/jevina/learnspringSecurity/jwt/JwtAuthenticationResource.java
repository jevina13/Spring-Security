package com.jevina.learnspringSecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;

//@RestController
public class JwtAuthenticationResource {

	private JwtEncoder jwtEncoder;

	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate") 
	public JwtResponse authenticate(Authentication authentication) {
		return new JwtResponse(createToken(authentication));
	} 
	
	record JwtResponse(String token) {
		
	}
	
	private String createToken(Authentication authentication) {
		var claims = JwtClaimsSet.builder()
								.issuer("self")			//who has issued
								.issuedAt(Instant.now())	//when issued
								.expiresAt(Instant.now().plusSeconds(60 * 30))	//when expires
								.subject(authentication.getName())			//who is subject
								.claim("scope", createScope(authentication))  //authorities of the specific user
								.build();
		
		return jwtEncoder.encode(JwtEncoderParameters.from(claims))
							.getTokenValue();
	}
	
	private String createScope(Authentication authentication) {
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority())				//getting all authorities together and
			.collect(Collectors.joining(" "));			//separating it by space
	}
	
}
