package com.ahmadre.hinata.auth;

import com.ahmadre.hinata.common.ApiException;
import com.ahmadre.hinata.config.ClientIpResolver;
import com.ahmadre.hinata.config.HinataProperties;
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
 * Public invite flow. The invitation email links to {@code .../invite/confirm},
 * a tiny landing page that hands off to the Flutter app via the
 * {@code hinata://invite} deep link (carrying the token + this server's URL) so
 * the invitee sets their password in the app's UI. The app then calls the JSON
 * endpoints here: {@code GET /invite/info} to show who is joining, and
 * {@code POST /invite/accept} to set the password and sign in immediately.
 */
@Tag(name = "Auth · Invite")
@RestController
@RequiredArgsConstructor
public class InviteController {

	private final UserRepository users;
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final AuthService authService;
	private final ClientIpResolver clientIpResolver;
	private final HinataProperties properties;

	// --- Email landing page → deep-link handoff into the app -----------------

	@Operation(summary = "Invitation landing page — opens the hinata app to set a password")
	@SecurityRequirements
	@GetMapping(value = "/api/v1/auth/invite/confirm", produces = MediaType.TEXT_HTML_VALUE)
	public String inviteLanding(@RequestParam String token) {
		try {
			resolve(token);
		}
		catch (ApiException ex) {
			return invalidPage();
		}
		String deepLink = "hinata://invite?token=" + enc(token) + "&server=" + enc(properties.getBaseUrl());
		return handoffPage(deepLink);
	}

	// --- JSON API used by the app --------------------------------------------

	public record InviteInfo(String email, String displayName) {
	}

	@Operation(summary = "Validate an invite token and return the invitee's email")
	@SecurityRequirements
	@GetMapping("/api/v1/auth/invite/info")
	public InviteInfo info(@RequestParam String token) {
		User user = resolve(token);
		return new InviteInfo(user.getEmail(), user.getDisplayName());
	}

	public record AcceptRequest(@NotBlank String token, @NotBlank String password) {
	}

	@Operation(summary = "Accept an invitation, set the password and sign in")
	@SecurityRequirements
	@PostMapping("/api/v1/auth/invite/accept")
	public AuthController.LoginResponse accept(@RequestBody @Valid AcceptRequest request,
			HttpServletRequest http) {
		User user = resolve(request.token());
		userService.validatePassword(request.password());
		user.setPasswordHash(passwordEncoder.encode(request.password()));
		user.setJoinedAt(Instant.now());
		user.setActive(true);
		user.setEmailVerified(true);
		user.setInviteTokenHash(null);
		user.setInviteExpiresAt(null);
		User saved = users.save(user);
		TokenService.TokenPair pair = authService.issueWithSession(saved,
				clientIpResolver.resolve(http), http.getHeader("User-Agent"));
		return new AuthController.LoginResponse(false, null, pair.accessToken(), pair.refreshToken(),
				pair.expiresInSeconds(), AuthController.UserResponse.from(saved));
	}

	/** Resolves a {@code userId.secret} invite token to its pending user, or 400s. */
	private User resolve(String token) {
		int dot = token == null ? -1 : token.indexOf('.');
		if (dot <= 0) throw ApiException.badRequest("error.user.inviteInvalid");
		String id = token.substring(0, dot);
		String secret = token.substring(dot + 1);
		User user = users.findById(id)
				.orElseThrow(() -> ApiException.badRequest("error.user.inviteInvalid"));
		if (!user.isInvitePending() || user.getInviteTokenHash() == null
				|| user.getInviteExpiresAt() == null
				|| user.getInviteExpiresAt().isBefore(Instant.now())
				|| !passwordEncoder.matches(secret, user.getInviteTokenHash())) {
			throw ApiException.badRequest("error.user.inviteInvalid");
		}
		return user;
	}

	private static String enc(String value) {
		return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
	}

	private String handoffPage(String deepLink) {
		String safe = HtmlUtils.htmlEscape(deepLink);
		return """
				<!doctype html><html><head><meta charset="utf-8"/>
				<meta name="viewport" content="width=device-width,initial-scale=1"/>
				<title>Open hinata</title>
				<meta http-equiv="refresh" content="0;url=%s"/>
				<script>window.location.replace("%s");</script></head>
				<body style="margin:0;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#F4F3EF">
				<div style="max-width:460px;margin:64px auto;background:#fff;border:1px solid #E7E5DE;border-radius:24px;overflow:hidden">
				<div style="height:4px;background:#D9A032"></div>
				<div style="padding:32px;text-align:center">
				<div style="font-weight:800;color:#2D2B55;margin-bottom:20px">hinata</div>
				<h1 style="color:#23223F;font-size:20px;margin:0 0 12px">Open the hinata app</h1>
				<p style="color:#6B6A85;font-size:15px;line-height:1.6;margin:0 0 24px">
				Finish setting up your account in the hinata app. If it didn't open automatically,
				tap the button below on the device where hinata is installed.</p>
				<a href="%s" style="display:inline-block;background:#2D2B55;color:#fff;padding:13px 26px;border-radius:24px;text-decoration:none;font-weight:600">Open hinata</a>
				</div></div></body></html>
				""".formatted(safe, safe, safe);
	}

	private String invalidPage() {
		return """
				<!doctype html><html><head><meta charset="utf-8"/>
				<meta name="viewport" content="width=device-width,initial-scale=1"/>
				<title>Invitation · hinata</title></head>
				<body style="margin:0;font-family:-apple-system,'Segoe UI',Roboto,sans-serif;background:#F4F3EF">
				<div style="max-width:460px;margin:64px auto;background:#fff;border:1px solid #E7E5DE;border-radius:24px;overflow:hidden">
				<div style="height:4px;background:#D9A032"></div>
				<div style="padding:32px;text-align:center">
				<div style="font-weight:800;color:#2D2B55;margin-bottom:20px">hinata</div>
				<h1 style="color:#23223F;font-size:20px;margin:0 0 12px">Invitation invalid or expired</h1>
				<p style="color:#6B6A85;font-size:15px;line-height:1.6;margin:0">
				Please ask an administrator to send you a fresh invitation.</p>
				</div></div></body></html>
				""";
	}
}
