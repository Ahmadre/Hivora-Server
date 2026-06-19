package com.ahmadre.hinata.me;

import com.ahmadre.hinata.user.User;
import com.ahmadre.hinata.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Stores and consumes 2FA recovery codes. Codes are only ever held as BCrypt
 * hashes; the plaintext set is shown to the user exactly once at generation.
 */
@Service
@RequiredArgsConstructor
public class RecoveryCodeService {

	private final PasswordEncoder passwordEncoder;
	private final UserRepository users;

	/** Hashes a freshly generated set for storage on the user document. */
	public List<String> hashAll(List<String> plainCodes) {
		List<String> hashes = new ArrayList<>(plainCodes.size());
		for (String code : plainCodes) {
			hashes.add(passwordEncoder.encode(normalize(code)));
		}
		return hashes;
	}

	/**
	 * If {@code input} matches an unused recovery code, removes it (single-use)
	 * and persists the user, returning true. Otherwise returns false.
	 */
	public boolean consume(User user, String input) {
		if (input == null || user.getRecoveryCodeHashes() == null) return false;
		String candidate = normalize(input);
		for (String hash : user.getRecoveryCodeHashes()) {
			if (passwordEncoder.matches(candidate, hash)) {
				user.getRecoveryCodeHashes().remove(hash);
				users.save(user);
				return true;
			}
		}
		return false;
	}

	private String normalize(String code) {
		return code.trim().toUpperCase(Locale.ROOT).replaceAll("\\s", "");
	}
}
