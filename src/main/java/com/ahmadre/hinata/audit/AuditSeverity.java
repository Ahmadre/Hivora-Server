package com.ahmadre.hinata.audit;

/**
 * Relative importance of an audit event — drives colour coding in the log and
 * lets operators scan for anything that warrants attention.
 */
public enum AuditSeverity {

	/** Routine, expected activity (a successful login, a profile edit). */
	INFO,

	/** Noteworthy or sensitive, but not necessarily a problem (2FA disabled,
	 *  admin promoted, settings changed). */
	NOTICE,

	/** Likely security-relevant and worth investigating (failed login, lockout,
	 *  account deletion). */
	WARNING
}
