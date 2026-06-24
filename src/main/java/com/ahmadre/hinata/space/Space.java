package com.ahmadre.hinata.space;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * A knowledge-base space ("Bereich") that groups articles, Confluence-style.
 *
 * <p>The space {@link #name} doubles as the key articles reference through
 * {@code Article.space} — keeping the existing name-based linkage while letting
 * spaces persist independently (so an empty space survives and carries its own
 * icon / hue / description instead of the formerly hard-coded catalog).
 */
@Data
@Builder
@Document("spaces")
public class Space {

	@Id
	private String id;

	/** Display name; also the key articles reference via {@code Article.space}. */
	@Indexed(unique = true)
	private String name;

	/** Lucide icon name (kebab-case) for the space glyph. */
	private String icon;

	/** Hue (0–360) driving the space's accent chrome. */
	private int hue;

	/** Short one-line description shown on the space card. */
	private String description;

	@Builder.Default
	private int sortOrder = 0;

	private String authorId;

	@CreatedDate
	private Instant createdAt;

	@LastModifiedDate
	private Instant updatedAt;
}
