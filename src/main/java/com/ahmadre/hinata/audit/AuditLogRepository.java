package com.ahmadre.hinata.audit;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.time.Instant;

/**
 * Persistence for {@link AuditLog}. Filtered/paged reads are built dynamically
 * in {@link AuditService} with a {@code Query}; this interface only carries the
 * housekeeping operations.
 */
public interface AuditLogRepository extends MongoRepository<AuditLog, String> {

	/** Retention sweep: drop everything older than the cut-off. */
	long deleteByTimestampBefore(Instant cutoff);
}
