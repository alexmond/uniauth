package org.alexmond.uniauth.admin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every custom property the stylesheet uses is one it defines.
 *
 * <p>
 * This exists because of a bug no rendered-HTML test could see. The account table was
 * written against invented variable names — {@code --dim}, {@code --line}, and worst,
 * {@code --ink} for text when {@code --ink} is this palette's <em>background</em>. The
 * markup was correct and every assertion on it passed; the usernames were simply painted
 * in the page background, so the column looked empty and the store looked like it held
 * nobody.
 *
 * <p>
 * An undefined custom property is invalid at computed-value time, which CSS resolves
 * silently rather than as an error — there is no console warning to notice and nothing
 * fails. Checking the file is the only cheap way to catch it.
 */
class StylesheetTest {

	private static final Pattern DEFINED = Pattern.compile("(?m)^\\s*(--[a-z-]+)\\s*:");

	private static final Pattern USED = Pattern.compile("var\\(\\s*(--[a-z-]+)");

	@Test
	void noRuleReferencesAVariableThatWasNeverDefined() throws IOException {
		String css = stylesheet();

		Set<String> defined = matches(DEFINED, css);
		Set<String> undefined = new TreeSet<>(matches(USED, css));
		undefined.removeAll(defined);
		// A var() with a fallback still works, so only bare references are reported —
		// but the fallback form hides typos, which is why the palette does not use it.
		undefined.removeIf((name) -> css.contains("var(" + name + ","));

		assertThat(undefined).as("custom properties used but never defined").isEmpty();
	}

	@Test
	void theTextAndBackgroundColoursAreNotTheSameVariable() {
		// The specific mistake: --ink is the background here, and reaching for it as a
		// text colour is an easy assumption to make from the name alone.
		assertThat(colourOf("--ink")).isNotEqualTo(colourOf("--bone"));
	}

	private String colourOf(String name) {
		Matcher matcher = Pattern.compile(Pattern.quote(name) + "\\s*:\\s*([^;]+);").matcher(stylesheetQuietly());
		assertThat(matcher.find()).as("%s is defined", name).isTrue();
		return matcher.group(1).trim();
	}

	private static Set<String> matches(Pattern pattern, String text) {
		Set<String> found = new TreeSet<>();
		Matcher matcher = pattern.matcher(text);
		while (matcher.find()) {
			found.add(matcher.group(1));
		}
		return found;
	}

	private String stylesheetQuietly() {
		try {
			return stylesheet();
		}
		catch (IOException ex) {
			throw new IllegalStateException(ex);
		}
	}

	private String stylesheet() throws IOException {
		try (InputStream in = getClass().getResourceAsStream("/static/css/uniauth.css")) {
			assertThat(in).as("the console stylesheet is on the classpath").isNotNull();
			return new String(in.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

}
