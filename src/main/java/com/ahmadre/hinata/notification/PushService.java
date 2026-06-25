package com.ahmadre.hinata.notification;

import com.ahmadre.hinata.config.HinataProperties;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.ErrorCode;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.AndroidConfig;
import com.google.firebase.messaging.ApnsConfig;
import com.google.firebase.messaging.Aps;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.MessagingErrorCode;
import com.google.firebase.messaging.Notification;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Sends FCM push to a user's registered devices. Initializes the Firebase Admin
 * SDK lazily from the configured service-account JSON; if FCM is disabled or the
 * credentials file is missing, every send is a silent no-op so the rest of the
 * notification pipeline (in-app + e-mail) is unaffected. Invalid/expired tokens
 * are pruned automatically so the device collection self-heals.
 */
@Service
@RequiredArgsConstructor
public class PushService {

	private static final Logger log = LoggerFactory.getLogger(PushService.class);

	private final HinataProperties props;
	private final DeviceTokenRepository devices;

	private volatile FirebaseMessaging messaging;

	@PostConstruct
	void init() {
		HinataProperties.Fcm fcm = props.getFcm();
		if (!fcm.isEnabled() || fcm.getCredentials() == null || fcm.getCredentials().isBlank()) {
			log.info("FCM push disabled (no credentials configured) — push sends will no-op.");
			return;
		}
		try (InputStream in = new FileInputStream(fcm.getCredentials())) {
			FirebaseOptions options = FirebaseOptions.builder()
					.setCredentials(GoogleCredentials.fromStream(in))
					.build();
			FirebaseApp app = FirebaseApp.getApps().isEmpty()
					? FirebaseApp.initializeApp(options)
					: FirebaseApp.getInstance();
			this.messaging = FirebaseMessaging.getInstance(app);
			log.info("FCM push enabled (project: {}, credentials: {}).",
					app.getOptions().getProjectId(), fcm.getCredentials());
		}
		catch (Exception e) {
			log.error("FCM init failed ({}). Push sends will no-op.", e.getMessage());
		}
	}

	/**
	 * Fan a notification out to every device the user has registered. Runs
	 * asynchronously so the originating request (assign issue, comment, …) is
	 * never blocked on the network round-trip to FCM.
	 */
	@Async
	public void sendToUser(String userId, String title, String body, String link) {
		if (messaging == null || userId == null) return;
		List<DeviceToken> tokens = devices.findByUserId(userId);
		for (DeviceToken device : tokens) {
			send(device, title, body, link);
		}
	}

	private void send(DeviceToken device, String title, String body, String link) {
		Map<String, String> data = new HashMap<>();
		if (link != null && !link.isBlank()) data.put("link", link);
		Message message = Message.builder()
				.setToken(device.getToken())
				.setNotification(Notification.builder().setTitle(title).setBody(body).build())
				.putAllData(data)
				// Tapping a notification should open the deep link / restore the app.
				.setAndroidConfig(AndroidConfig.builder()
						.setPriority(AndroidConfig.Priority.HIGH).build())
				.setApnsConfig(ApnsConfig.builder()
						.setAps(Aps.builder().setSound("default").build()).build())
				.build();
		try {
			messaging.send(message);
		}
		catch (FirebaseMessagingException e) {
			if (isDeadToken(e)) {
				// Token no longer valid (app uninstalled, token rotated, wrong sender):
				// drop it so the device collection self-heals and stops failing.
				devices.deleteByToken(device.getToken());
				log.debug("Pruned dead FCM token for user {} ({}).", device.getUserId(), e.getMessagingErrorCode());
			}
			else {
				log.warn("FCM send failed ({}): {}", e.getMessagingErrorCode(), e.getMessage());
			}
		}
	}

	/**
	 * A send failure that means <em>this token will never deliver again</em> — so
	 * the token should be pruned rather than retried/logged forever. FCM signals an
	 * unregistered token with HTTP 404 ("Requested entity was not found"). The Admin
	 * SDK usually maps that to {@link MessagingErrorCode#UNREGISTERED}, but when the
	 * 404 error body can't be parsed (seen in the wild as "Not in GZIP format") the
	 * messaging-specific code comes back {@code null}; the generic
	 * {@link ErrorCode#NOT_FOUND} / the raw HTTP 404 still identify it, so we fall
	 * back to those. INVALID_ARGUMENT (malformed token) and SENDER_ID_MISMATCH
	 * (token belongs to another sender) are likewise unrecoverable for this token.
	 */
	private boolean isDeadToken(FirebaseMessagingException e) {
		MessagingErrorCode code = e.getMessagingErrorCode();
		if (code == MessagingErrorCode.UNREGISTERED
				|| code == MessagingErrorCode.INVALID_ARGUMENT
				|| code == MessagingErrorCode.SENDER_ID_MISMATCH) {
			return true;
		}
		if (e.getErrorCode() == ErrorCode.NOT_FOUND || e.getErrorCode() == ErrorCode.INVALID_ARGUMENT) {
			return true;
		}
		return e.getHttpResponse() != null && e.getHttpResponse().getStatusCode() == 404;
	}
}
