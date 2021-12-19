/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector;
import com.nimbusds.jwt.proc.JWTProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

/**
 * @author Josh Cummings
 */
@EnableWebSecurity
public class OAuth2ResourceServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authorizeRequests) -> 
				authorizeRequests
					.antMatchers(HttpMethod.GET, "/message/**").hasAuthority("SCOPE_message:read")
					.antMatchers(HttpMethod.POST, "/message/**").hasAuthority("SCOPE_message:write")
					.anyRequest().authenticated()
			)
			.oauth2ResourceServer(oauth -> {
				oauth.jwt();
				DefaultBearerTokenResolver tokenResolver = new DefaultBearerTokenResolver();
				tokenResolver.setAllowFormEncodedBodyParameter(true);
				tokenResolver.setAllowUriQueryParameter(true);
				oauth.bearerTokenResolver(tokenResolver);
			});
		// @formatter:on
	}

	// 12.3.21. Bearer Token Resolution
	/**
	 * JWT 위치 커스터마이징
	 * 1. header 의 HT-Access-Token
	 * 2. request parameter 의 access_token
	 * 3. url parameter 의 access_token
	 * 4. Bearer
	 */

	@Bean
	JWTProcessor jwtProcessor(JWTClaimsSetAwareJWSKeySelector keySelector) {
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWTClaimsSetAwareJWSKeySelector(keySelector);
		return jwtProcessor;
	}

	@Bean
	JwtDecoder jwtDecoder(JWTProcessor jwtProcessor) {
		return new NimbusJwtDecoder(jwtProcessor);
	}

//	@Bean
//	JwtDecoder jwtDecoder() {
//		return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
//	}
}
