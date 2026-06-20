package com.ahmadre.hinata.audit;

import com.ahmadre.hinata.setup.SettingsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Nightly sweep that drops audit records older than the configured retention
 * window ({@code audit.retentionDays}). A value of {@code 0} keeps records
 * forever. Scheduling is enabled application-wide on the main class.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditRetentionJob {

	private final AuditLogRepository repository;
	private final SettingsService settings;

	/** Runs daily at 03:30 server time. */
	@Scheduled(cron = "0 30 3 * * *")
	public void purgeExpired() {
		int days = settings.get().getAudit().getRetentionDays();
		if (days <= 0) {
			return; // keep forever
		}
		Instant cutoff = Instant.now().minus(Duration.ofDays(days));
		long removed = repository.deleteByTimestampBefore(cutoff);
		if (removed > 0) {
			log.info("[audit] retention sweep removed {} record(s) older than {} day(s)", removed, days);
		}
	}
}
