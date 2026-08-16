package org.alexmond.uniauth.admin.store;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The directory store, against a real directory rather than a mock.
 *
 * <p>
 * A mock would prove only that the right methods were called. What is actually worth
 * testing here is what a directory does back: it enforces a schema, it refuses a
 * duplicate DN, and it will not modify an entry that is not there. None of that survives
 * being stubbed.
 */
@SpringBootTest
@TestPropertySource(properties = { "console.provider.enabled=false", "spring.ldap.embedded.base-dn=dc=example,dc=com",
		"spring.ldap.embedded.ldif=classpath:console-directory.ldif", "spring.ldap.embedded.port=18391",
		"spring.ldap.embedded.credential.username=cn=admin,dc=example,dc=com",
		"spring.ldap.embedded.credential.password=admin-pass",
		"console.directory.url=ldap://localhost:18391/dc=example,dc=com",
		"console.directory.manager-dn=cn=admin,dc=example,dc=com", "console.directory.manager-password=admin-pass" })
class DirectoryUserStoreTest {

	@Autowired
	List<UserStore> stores;

	private UserStore directory() {
		return this.stores.stream()
			.filter((store) -> "directory".equals(store.id()))
			.findFirst()
			.orElseThrow(() -> new AssertionError("no directory store configured"));
	}

	@Test
	void itListsTheEntriesThatAreThere() {
		assertThat(directory().users()).extracting(ConsoleUser::username).contains("bob");
	}

	@Test
	void itReportsWhereAnEntryLives() {
		// The DN is the answer to "which of the several places called bob is this one",
		// so it is shown rather than hidden behind the username.
		assertThat(directory().users()).filteredOn((user) -> user.username().equals("bob"))
			.singleElement()
			.satisfies((user) -> assertThat(user.detail()).isEqualTo("uid=bob,ou=people,dc=example,dc=com"));
	}

	@Test
	void aCreatedEntryIsThereAfterwards() {
		directory().create("carol", "carols-password", List.of());

		assertThat(directory().users()).extracting(ConsoleUser::username).contains("carol");
	}

	@Test
	void creatingTheSameEntryTwiceIsRefusedWithSomethingReadable() {
		directory().create("duplicate", "pw", List.of());

		assertThatThrownBy(() -> directory().create("duplicate", "pw", List.of())).isInstanceOf(StoreException.class)
			.hasMessageContaining("already has an entry");
	}

	@Test
	void aPasswordCanBeReplaced() {
		directory().create("rotate", "first", List.of());

		directory().setPassword("rotate", "second");

		assertThat(directory().users()).extracting(ConsoleUser::username).contains("rotate");
	}

	@Test
	void changingThePasswordOfSomebodyWhoIsNotThereSaysSo() {
		assertThatThrownBy(() -> directory().setPassword("ghost", "pw")).isInstanceOf(StoreException.class)
			.hasMessageContaining("no entry for ghost");
	}

	@Test
	void aRemovedEntryIsGone() {
		directory().create("temporary", "pw", List.of());

		directory().delete("temporary");

		assertThat(directory().users()).extracting(ConsoleUser::username).doesNotContain("temporary");
	}

	@Test
	void removingSomebodyWhoIsNotThereSaysSo() {
		assertThatThrownBy(() -> directory().delete("ghost")).isInstanceOf(StoreException.class)
			.hasMessageContaining("no entry for ghost");
	}

	@Test
	void rolesAreNotEditableHere() {
		// Groups are entries with their own members. Offering them as a field on a person
		// would suggest they live on the person, which is the opposite of how the
		// applications resolve them.
		assertThat(directory().supportsRoles()).isFalse();
		assertThatThrownBy(() -> directory().setRoles("bob", List.of("ADMIN"))).isInstanceOf(StoreException.class);
	}

}
