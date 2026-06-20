package com.ahmadre.hinata.auth;

import com.ahmadre.hinata.common.ApiException;
import com.ahmadre.hinata.config.ClientIpResolver;
import com.ahmadre.hinata.config.HinataProperties;
import com.ahmadre.hinata.me.SessionService;
import com.ahmadre.hinata.user.User;
import com.ahmadre.hinata.user.UserRepository;
import com.ahmadre.hinata.user.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Public password-reset flow that hands off to the Flutter app. The reset email
 * links to {@code .../reset/confirm}, a landing page that opens the app via the
 * {@code hinata://reset-password} deep link so the user picks a new password in
 * the app UI. The app posts to {@code /reset/accept}, which sets the password,
 * revokes existing sessions and signs the user in. Reuses the one-time token
 * stored on {@link User#getPasswordResetTokenHash()}.
 */
@Tag(name = "Auth · Password reset")
@RestController
@RequiredArgsConstructor
public class PasswordResetController {

	private final UserRepository users;
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final AuthService authService;
	private final SessionService sessions;
	private final ClientIpResolver clientIpResolver;
	private final HinataProperties properties;

	@Operation(summary = "Password-reset landing page — opens the hinata app")
	@SecurityRequirements
	@GetMapping(value = "/api/v1/auth/reset/confirm", produces = MediaType.TEXT_HTML_VALUE)
	public String landing(@RequestParam String token) {
		try {
			resolve(token);
		}
		catch (ApiException ex) {
			return page("Reset link invalid or expired",
					"Please request a new password-reset link.", null);
		}
		String deepLink = "hinata://reset-password?token=" + enc(token)
				+ "&server=" + enc(properties.getBaseUrl());
		return page("Open the hinata app",
				"Choose your new password in the hinata app. If it didn't open automatically, "
						+ "tap the button below on the device where hinata is installed.",
				deepLink);
	}

	public record AcceptRequest(@NotBlank String token, @NotBlank String password) {
	}

	@Operation(summary = "Set a new password from a reset link and sign in")
	@SecurityRequirements
	@PostMapping("/api/v1/auth/reset/accept")
	public AuthController.LoginResponse accept(@RequestBody @Valid AcceptRequest request,
			HttpServletRequest http) {
		User user = resolve(request.token());
		userService.validatePassword(request.password());
		user.setPasswordHash(passwordEncoder.encode(request.password()));
		user.setPasswordChangedAt(Instant.now());
		user.setPasswordResetTokenHash(null);
		user.setPasswordResetExpiresAt(null);
		User saved = users.save(user);
		sessions.revokeAll(saved.getId()); // sign out every existing device
		TokenService.TokenPair pair = authService.issueWithSession(saved,
				clientIpResolver.resolve(http), http.getHeader("User-Agent"));
		return new AuthController.LoginResponse(false, null, pair.accessToken(), pair.refreshToken(),
				pair.expiresInSeconds(), AuthController.UserResponse.from(saved));
	}

	/** Resolves a {@code userId.secret} reset token to its user, or 400s. */
	private User resolve(String token) {
		int dot = token == null ? -1 : token.indexOf('.');
		if (dot <= 0) throw ApiException.badRequest("error.me.passwordResetInvalid");
		String id = token.substring(0, dot);
		String secret = token.substring(dot + 1);
		User user = users.findById(id)
				.orElseThrow(() -> ApiException.badRequest("error.me.passwordResetInvalid"));
		if (user.getPasswordResetTokenHash() == null || user.getPasswordResetExpiresAt() == null
				|| user.getPasswordResetExpiresAt().isBefore(Instant.now())
				|| !passwordEncoder.matches(secret, user.getPasswordResetTokenHash())) {
			throw ApiException.badRequest("error.me.passwordResetInvalid");
		}
		return user;
	}

	private static String enc(String value) {
		return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
	}

	private String page(String title, String body, String deepLink) {
		String safeTitle = HtmlUtils.htmlEscape(title);
		String safeBody = HtmlUtils.htmlEscape(body);
		String head = deepLink == null ? "" : """
				<meta http-equiv="refresh" content="0;url=%s"/>
				<script>window.location.replace("%s");</script>"""
				.formatted(HtmlUtils.htmlEscape(deepLink), HtmlUtils.htmlEscape(deepLink));
		String button = deepLink == null ? "" : """
				<a href="%s" style="display:inline-block;background:#2D2B55;color:#fff;padding:13px 26px;border-radius:24px;text-decoration:none;font-weight:600">Open hinata</a>"""
				.formatted(HtmlUtils.htmlEscape(deepLink));
		return """
				<!doctype html><html><head><meta charset="utf-8"/>
				<meta name="viewport" content="width=device-width,initial-scale=1"/>
				<title>hinata</title>%s</head>
				<body style="margin:0;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#F4F3EF">
				<div style="max-width:460px;margin:64px auto;background:#fff;border:1px solid #E7E5DE;border-radius:24px;overflow:hidden">
				<div style="height:4px;background:#D9A032"></div>
				<div style="padding:32px;text-align:center">
				<div style="font-weight:800;color:#2D2B55;margin-bottom:20px">hinata</div>
				<h1 style="color:#23223F;font-size:20px;margin:0 0 12px">%s</h1>
				<p style="color:#6B6A85;font-size:15px;line-height:1.6;margin:0 0 24px">%s</p>
				%s
				</div></div></body></html>
				""".formatted(head, safeTitle, safeBody, button);
	}
}
