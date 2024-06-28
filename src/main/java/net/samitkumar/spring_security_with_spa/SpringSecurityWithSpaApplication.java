package net.samitkumar.spring_security_with_spa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;

import java.security.Principal;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class SpringSecurityWithSpaApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityWithSpaApplication.class, args);
	}
}

@RestController
@RequiredArgsConstructor
@Slf4j
class ApplicationController {
	SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();

	@PostMapping("/logout")
	public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
		this.securityContextLogoutHandler.logout(request, response, authentication);
		return "redirect:/";
	}

	@GetMapping("/csrf")
	@ResponseBody
	public CsrfToken csrf(CsrfToken csrfToken) {
		return csrfToken;
	}

	@GetMapping("/api/me")
	@ResponseBody
	public Principal me(Principal principal, @RequestHeader Map<Object, Object> headers) {
		log.info("Headers: {}", headers);
		return principal;
	}
}

@Configuration
@EnableWebSecurity
class SecurityConfiguration {
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				.csrf(csrf -> csrf
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				)
				//.csrf(Customizer.withDefaults())
				.cors(cors -> cors.configurationSource(request -> {
							var corsConfig = new CorsConfiguration();
							corsConfig.setAllowedOriginPatterns(List.of("*"));
							corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
							corsConfig.setAllowedHeaders(List.of("*"));
							corsConfig.setAllowCredentials(true);
							return corsConfig;
						})
				)
				.authorizeHttpRequests(httpRequest -> httpRequest
						.requestMatchers(HttpMethod.GET, "/", "/index.html", "/favicon.ico", "/csrf").permitAll()
						.anyRequest().authenticated()
				)
				//.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.formLogin((form) -> form
						.successHandler((request, response, authentication) -> response.setStatus(HttpStatus.OK.value()))
						.failureHandler((request, response, exception) -> response.sendError(HttpStatus.UNAUTHORIZED.value()))
				)
				.logout(logout -> logout
						.logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpStatus.OK.value()))
				)
				.exceptionHandling(ex -> ex
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
				)
				.build();
	}
}