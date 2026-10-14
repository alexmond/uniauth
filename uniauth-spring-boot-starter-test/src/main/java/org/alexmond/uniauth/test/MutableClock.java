package org.alexmond.uniauth.test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A clock the test moves, so one store can be carried through time.
 *
 * <p>
 * The alternative — a second store on a later {@code Clock.fixed} — needs the first
 * store's contents copied into it, which no SPI method offers and which an in-memory
 * implementation can only do through a package-private seam. Moving the clock instead
 * keeps the store under test the same object it always was.
 *
 * <p>
 * It also tests something worth testing. A store is handed a {@code Clock} because it is
 * expected to read it when it needs the time; one that calls {@code instant()} once in
 * its constructor and keeps the answer will report an invitation as open for ever, and
 * only a clock that actually moves will show it.
 */
public final class MutableClock extends Clock {

	private final ZoneId zone;

	/**
	 * An atomic reference rather than a volatile field: the concurrency cases read this
	 * clock from every racing thread, so the write has to be visible to all of them.
	 */
	private final AtomicReference<Instant> instant = new AtomicReference<>();

	/**
	 * @param instant what {@link #instant()} answers until it is moved
	 */
	public MutableClock(Instant instant) {
		this(instant, ZoneId.of("UTC"));
	}

	private MutableClock(Instant instant, ZoneId zone) {
		this.instant.set(instant);
		this.zone = zone;
	}

	/**
	 * Moves the clock.
	 * @param to the new now; may be earlier than the current value, which no test here
	 * needs but which costs nothing to allow
	 */
	public void set(Instant to) {
		this.instant.set(to);
	}

	@Override
	public Instant instant() {
		return this.instant.get();
	}

	@Override
	public ZoneId getZone() {
		return this.zone;
	}

	@Override
	public Clock withZone(ZoneId other) {
		return new MutableClock(this.instant.get(), other);
	}

}
