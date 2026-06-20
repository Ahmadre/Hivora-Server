package com.ahmadre.hinata.audit;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.Map;

/**
 * One immutable security-audit record. Written by {@link AuditService} whenever a
 * recorded {@link AuditAction} occurs and the action is enabled in the runtime
 * audit settings. Never updated after creation.
 */
@Data
@Builder
@Document("audit_log")
public class AuditLog {

	public enum Outcome {
		SUCCESS, FAILURE
	}

	@Id
	private String id;

	@Indexed
	@CreatedDate
	private Instant timestamp;

	@Indexed
	private AuditAction action;

	@Indexed
	private AuditCategory category;

	private AuditSeverity severity;

	private Outcome outcome;

	/** Id of the user who performed the action, when known (null for anonymous). */
	@Indexed
	private String actorId;

	/** Human label for the actor — display name, or the identifier they typed. */
	private String actorLabel;

	/** Id of the object the action targeted (another user, a setting…), if any. */
	private String targetId;

	/** Human label for the target — e.g. the affected user's name. */
	private String targetLabel;

	/** Masked client IP (last octets hidden) the action originated from. */
	private String ip;

	/** Best-effort client/device string from the User-Agent. */
	private String userAgent;

	/** Optional structured detail (old → new role, lockout minutes, …). */
	private Map<String, String> metadata;
}
