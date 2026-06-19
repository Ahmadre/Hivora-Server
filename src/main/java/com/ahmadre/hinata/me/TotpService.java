package com.ahmadre.hinata.me;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 6238 TOTP (SHA-1, 6 digits, 30 s period) plus Base32 secret generation
 * and recovery-code minting. Uses the JDK's vetted {@link Mac} HMAC primitive —
 * no hand-rolled crypto. Verification allows a ±1 period (30 s) clock skew.
 */
@Service
public class TotpService {

	private static final int DIGITS = 6;
	private static final int PERIOD_SECONDS = 30;
	private static final int SKEW_PERIODS = 1;
	private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	private static final SecureRandom RANDOM = new SecureRandom();

	/** A new 160-bit secret, Base32-encoded (no padding). */
	public String newSecret() {
		byte[] bytes = new byte[20];
		RANDOM.nextBytes(bytes);
		return base32Encode(bytes);
	}

	/** The {@code otpauth://} provisioning URI an authenticator app scans. */
	public String otpauthUri(String issuer, String accountEmail, String secret) {
		String label = enc(issuer) + ":" + enc(accountEmail);
		return "otpauth://totp/" + label + "?secret=" + secret
				+ "&issuer=" + enc(issuer)
				+ "&algorithm=SHA1&digits=" + DIGITS + "&period=" + PERIOD_SECONDS;
	}

	/** Validates a 6-digit code against {@code secret} within the skew window. */
	public boolean verify(String secret, String code) {
		if (secret == null || code == null) return false;
		String trimmed = code.trim().replaceAll("\\s", "");
		if (!trimmed.matches("\\d{" + DIGITS + "}")) return false;
		long counter = System.currentTimeMillis() / 1000L / PERIOD_SECONDS;
		for (int offset = -SKEW_PERIODS; offset <= SKEW_PERIODS; offset++) {
			if (trimmed.equals(generate(secret, counter + offset))) return true;
		}
		return false;
	}

	/** Ten human-friendly recovery codes (xxxxx-xxxxx). Shown once, then hashed. */
	public List<String> newRecoveryCodes() {
		List<String> codes = new ArrayList<>(10);
		for (int i = 0; i < 10; i++) {
			codes.add(group(randomAlphanumeric()) );
		}
		return codes;
	}

	private String generate(String base32Secret, long counter) {
		try {
			byte[] key = base32Decode(base32Secret);
			byte[] data = new byte[8];
			for (int i = 7; i >= 0; i--) {
				data[i] = (byte) (counter & 0xff);
				counter >>= 8;
			}
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(new SecretKeySpec(key, "HmacSHA1"));
			byte[] hash = mac.doFinal(data);
			int offset = hash[hash.length - 1] & 0x0f;
			int binary = ((hash[offset] & 0x7f) << 24)
					| ((hash[offset + 1] & 0xff) << 16)
					| ((hash[offset + 2] & 0xff) << 8)
					| (hash[offset + 3] & 0xff);
			int otp = binary % (int) Math.pow(10, DIGITS);
			return String.format("%0" + DIGITS + "d", otp);
		}
		catch (Exception ex) {
			return "";
		}
	}

	private String randomAlphanumeric() {
		String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous chars
		StringBuilder sb = new StringBuilder(10);
		for (int i = 0; i < 10; i++) {
			sb.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
		}
		return sb.toString();
	}

	private String group(String ten) {
		return ten.substring(0, 5) + "-" + ten.substring(5);
	}

	private static String enc(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

	private static String base32Encode(byte[] data) {
		StringBuilder result = new StringBuilder();
		int buffer = 0;
		int bitsLeft = 0;
		for (byte b : data) {
			buffer = (buffer << 8) | (b & 0xff);
			bitsLeft += 8;
			while (bitsLeft >= 5) {
				int index = (buffer >> (bitsLeft - 5)) & 0x1f;
				bitsLeft -= 5;
				result.append(BASE32.charAt(index));
			}
		}
		if (bitsLeft > 0) {
			int index = (buffer << (5 - bitsLeft)) & 0x1f;
			result.append(BASE32.charAt(index));
		}
		return result.toString();
	}

	private static byte[] base32Decode(String encoded) {
		String clean = encoded.trim().replaceAll("=+$", "").toUpperCase().replaceAll("\\s", "");
		int outLength = clean.length() * 5 / 8;
		byte[] result = new byte[outLength];
		int buffer = 0;
		int bitsLeft = 0;
		int index = 0;
		for (char c : clean.toCharArray()) {
			int value = BASE32.indexOf(c);
			if (value < 0) continue;
			buffer = (buffer << 5) | value;
			bitsLeft += 5;
			if (bitsLeft >= 8) {
				result[index++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xff);
				bitsLeft -= 8;
			}
		}
		return result;
	}
}
