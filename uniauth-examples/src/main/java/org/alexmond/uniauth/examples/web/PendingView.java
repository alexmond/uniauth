package org.alexmond.uniauth.examples.web;

import org.alexmond.uniauth.approval.ApprovalRecord;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * One row of the approval queue, shaped for reading.
 *
 * <p>
 * Exists mostly to keep {@code Instant.toString()} off the page: nanosecond precision is
 * true but useless to whoever is deciding, and long enough to wrap the column.
 *
 * @param principal who is waiting
 * @param provider the registration that vouched for them
 * @param mechanism which mechanism that was
 * @param firstSeen when they first turned up, to the minute
 */
public record PendingView(String principal, String provider, String mechanism, String firstSeen) {

	private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
		.withZone(ZoneOffset.UTC);

	public static PendingView of(ApprovalRecord record) {
		return new PendingView(record.key().principal(), record.key().provider(), record.mechanism().name(),
				STAMP.format(record.firstSeen()));
	}

}
