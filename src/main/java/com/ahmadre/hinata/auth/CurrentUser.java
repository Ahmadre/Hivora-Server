package com.ahmadre.hinata.auth;

import com.ahmadre.hinata.common.ApiException;
import com.ahmadre.hinata.user.User;
import com.ahmadre.hinata.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

/** Resolves the authenticated {@link User} from the JWT in the security context. */
@Component
@RequiredArgsConstructor
public class CurrentUser {

	private final UserRepository users;

	public User require() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof JwtAuthenticationToken jwt) {
			return users.findById(jwt.getToken().getSubject())
					.filter(User::isActive)
					.orElseThrow(() -> ApiException.unauthorized("error.auth.unknownUser"));
		}
		throw ApiException.unauthorized("error.auth.required");
	}

	public String requireId() {
		return require().getId();
	}

	/** The session id ({@code sid}) of the calling access token, or null (legacy token). */
	public String currentSessionId() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof JwtAuthenticationToken jwt) {
			return com.ahmadre.hinata.auth.TokenService.sessionId(jwt.getToken());
		}
		return null;
	}
}
