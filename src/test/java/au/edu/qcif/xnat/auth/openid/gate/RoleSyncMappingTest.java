package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Parsed;
import au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason;
import au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Rejected;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.List;

import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.EMPTY_PATH_STEP;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.EQUALS_IN_TOKEN_ROLE;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.HIDDEN_CHARACTER;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.MISPLACED_QUOTE;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.NO_CLAIM_PATH;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.NO_COLON;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.NO_EQUALS;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.NO_TOKEN_ROLE;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.NO_XNAT_ROLE;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.SPACE_IN_CLAIM_PATH;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.UNCLOSED_QUOTE;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.URL_CLAIM_NAME;
import static au.edu.qcif.xnat.auth.openid.gate.RoleSyncMapping.Reason.WRONG_QUOTE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link RoleSyncMapping}: how a {@code roleSync.mappings} value is cut into entries and each
 * entry into a claim path, a token role, and an XNAT role, and why an entry is rejected.
 */
@RunWith(Enclosed.class)
public class RoleSyncMappingTest {

    /** The character at {@code codePoint}, so that invisible characters never appear in this file. */
    private static String ch(final int codePoint) {
        return new String(Character.toChars(codePoint));
    }

    /** One entry, each row naming the single reason it is rejected for. */
    @RunWith(Parameterized.class)
    public static class RejectsAnEntry {

        @Parameters(name = "{0} is rejected: {1}")
        public static Object[][] examples() {
            return new Object[][] {
                    {"groups:admins" + ch(0x0009) + "=Admin", HIDDEN_CHARACTER}, // a tab inside; one at either end is trimmed
                    {"groups:admins" + ch(0x00A0) + "=Admin", HIDDEN_CHARACTER}, // a non-breaking space
                    {"groups:ad" + ch(0x200B) + "mins=Admin", HIDDEN_CHARACTER}, // a zero-width space
                    {"groups:admins=Admin" + ch(0xE0020), HIDDEN_CHARACTER}, // a formatting character beyond 0xFFFF
                    {"groups:admins=" + ch(0x00A0) + "Admin", HIDDEN_CHARACTER}, // a non-breaking space starting the XNAT role
                    {ch(0xFEFF) + "groups:admins=Admin", HIDDEN_CHARACTER}, // a byte-order mark, as pasted from some editors
                    {"groups:data" + ch(0x3000) + "team=Admin", HIDDEN_CHARACTER}, // an ideographic space
                    {"\"cognito:groups:admins=Administrator", UNCLOSED_QUOTE},  // the ':' after it is inside the quotes
                    {"\"a:b\"=Admin", NO_COLON},                          // the only ':' is inside the quotes
                    {"admins=Admin", NO_COLON},
                    {"=", NO_COLON},
                    {"groups:admins", NO_EQUALS},
                    {":", NO_EQUALS},
                    {"a=b:c", NO_EQUALS},                                // the only '=' comes before the ':'
                    {":admins=Admin", NO_CLAIM_PATH},
                    {"  :admins=Admin", NO_CLAIM_PATH},
                    {"resource_access..roles:admins=Admin", EMPTY_PATH_STEP},
                    {".groups:admins=Admin", EMPTY_PATH_STEP},
                    {"groups.:admins=Admin", EMPTY_PATH_STEP},
                    {".:admins=Admin", EMPTY_PATH_STEP},                 // a path that is only a dot
                    {"groups. .roles:admins=Admin", EMPTY_PATH_STEP},
                    {"\"\":admins=Admin", EMPTY_PATH_STEP},                  // an empty quoted name
                    {"resource_access.\"\".roles:admins=Admin", EMPTY_PATH_STEP},
                    {"\"a\"b:admins=Admin", MISPLACED_QUOTE},             // the quotes don't reach the end of the name
                    {"a\"b\":admins=Admin", MISPLACED_QUOTE},             // the quotes don't start the name
                    {"\"a\"\"b\":admins=Admin", MISPLACED_QUOTE},          // a quote inside a quoted name
                    {"groups:\"a\"b=Admin", MISPLACED_QUOTE},              // in the token role
                    {"groups:admins=\"A\"b", MISPLACED_QUOTE},             // in the XNAT role
                    {"groups:\"admins=Administrator", UNCLOSED_QUOTE},
                    {"\"cognito" + ch(0x00A0) + "groups\":admins=Admin", HIDDEN_CHARACTER}, // hidden even inside quotes
                    // Only a straight double quote takes a name as written; a name can't start with another kind.
                    {"'cognito:groups':admins=Administrator", WRONG_QUOTE},  // single quotes
                    {"`cognito:groups`:admins=Administrator", WRONG_QUOTE},  // backticks
                    {ch(0x201C) + "cognito:groups" + ch(0x201D) + ":admins=Administrator", WRONG_QUOTE}, // curly double quotes
                    {ch(0x201D) + "cognito:groups" + ch(0x201D) + ":admins=Administrator", WRONG_QUOTE}, // a closing curly quote
                    {ch(0x2018) + "cognito:groups" + ch(0x2019) + ":admins=Administrator", WRONG_QUOTE}, // curly single quotes
                    {ch(0x201A) + "groups" + ch(0x2018) + ":admins=Admin", WRONG_QUOTE}, // a low single quote
                    {ch(0x201E) + "groups" + ch(0x201C) + ":admins=Admin", WRONG_QUOTE}, // a low double quote
                    {"resource_access.'my.client'.roles:admin=Administrator", WRONG_QUOTE}, // inside a claim path
                    {"groups:'admins'=Administrator", WRONG_QUOTE},        // around the token role
                    {"groups:admins='Administrator'", WRONG_QUOTE},        // around the XNAT role
                    {"resource_access. xnat.roles:admins=Admin", SPACE_IN_CLAIM_PATH}, // a space after a dot
                    {"resource_access.xnat .roles:admins=Admin", SPACE_IN_CLAIM_PATH}, // a space before a dot
                    {"my client.roles:admins=Admin", SPACE_IN_CLAIM_PATH},
                    {"groups:=Admin", NO_TOKEN_ROLE},
                    {"groups: =Admin", NO_TOKEN_ROLE},
                    {"groups:\"\"=Admin", NO_TOKEN_ROLE},                  // nothing inside the quotes
                    {"https://example.org/roles:admins=Admin", URL_CLAIM_NAME}, // unquoted, so cut at the URL's ':'
                    {"groups:a=b=Admin", EQUALS_IN_TOKEN_ROLE},          // cut at the last '=', so 'a=b' is the token role
                    {"groups:xnat-access=XnatIQ groups:xnat-admin=Administrator", EQUALS_IN_TOKEN_ROLE}, // a missing comma
                    {"groups:xnat-access=XnatIQ; groups:xnat-admin=Administrator", EQUALS_IN_TOKEN_ROLE}, // a semicolon for a comma
                    {"groups:admins=", NO_XNAT_ROLE},
                    {"groups:admins= ", NO_XNAT_ROLE},
                    {"groups:admins=\"\"", NO_XNAT_ROLE},                  // nothing inside the quotes
                    // An entry with several faults gets the reason of the first check it fails.
                    {"admins=Admin" + ch(0x00A0), HIDDEN_CHARACTER},     // before NO_COLON
                    {":=", NO_CLAIM_PATH},                               // before NO_TOKEN_ROLE and NO_XNAT_ROLE
                    {"a..b: =", EMPTY_PATH_STEP},                        // before NO_TOKEN_ROLE and NO_XNAT_ROLE
                    {". a:x=y=", EMPTY_PATH_STEP},                       // before SPACE_IN_CLAIM_PATH and EQUALS_IN_TOKEN_ROLE
                    {"a b:x=y=", SPACE_IN_CLAIM_PATH},                   // before EQUALS_IN_TOKEN_ROLE and NO_XNAT_ROLE
                    {"groups:x=y=", EQUALS_IN_TOKEN_ROLE},               // before NO_XNAT_ROLE
            };
        }

        @Parameter(0) public String entry;
        @Parameter(1) public Reason reason;

        @Test
        public void forItsReason() {
            final Parsed parsed = RoleSyncMapping.parse(entry);

            assertTrue(parsed.mappings().isEmpty());
            assertEquals(1, parsed.rejected().size());
            assertEquals(reason, parsed.rejected().get(0).reason());
        }
    }

    /** One entry, each row naming the three parts it is cut into. */
    @RunWith(Parameterized.class)
    public static class AcceptsAnEntry {

        /** Words in a non-Latin script, written as code points. */
        private static final String NON_ASCII_PATH       = ch(0xADF8) + ch(0xB8F9);
        private static final String NON_ASCII_TOKEN_ROLE = ch(0xAD00) + ch(0xB9AC) + ch(0xC790);
        private static final String NON_ASCII_XNAT_ROLE  = ch(0xB2F4) + ch(0xB2F9) + ch(0xC790);

        @Parameters(name = "{0}")
        public static Object[][] examples() {
            return new Object[][] {
                    // entry                                                 claim path                    token role    XNAT role
                    {"resource_access.xnat.roles:xnat-admin=Administrator", "resource_access.xnat.roles", "xnat-admin", "Administrator"},
                    {"  groups : admins =  Administrator  ",                "groups",                     "admins",     "Administrator"},
                    {ch(0x0009) + "groups:admins=Administrator" + ch(0x000A), "groups",                   "admins",     "Administrator"},
                    {"groups:team:lead=a:b:c",                              "groups",                     "team:lead",  "a:b:c"},
                    {"groups:data team=Data Manager",                       "groups",                     "data team",  "Data Manager"},
                    {"groups:admins=administrator",                         "groups",                     "admins",     "administrator"},
                    {"roles:" + ch(0x1F600) + "=Admin",                      "roles",                      ch(0x1F600),  "Admin"},
                    {"a=b.roles:admins=Admin",                              "a=b.roles",                  "admins",     "Admin"}, // '=' in a claim path is kept
                    {"\"cognito:groups\":admins=Administrator",            "\"cognito:groups\"",         "admins",     "Administrator"},
                    {"\"https://myapp.example.com/roles\":admin=Administrator", "\"https://myapp.example.com/roles\"", "admin", "Administrator"},
                    {"resource_access.\"my.client\".roles:admin=Administrator", "resource_access.\"my.client\".roles", "admin", "Administrator"},
                    {"\"data team\":admins=Admin",                        "\"data team\"",              "admins",     "Admin"}, // a space inside quotes
                    // A quoted token role or XNAT role is taken as written, without its quotes.
                    {"groups:\"cn=admins,ou=groups,dc=example,dc=org\"=Administrator", "groups", "cn=admins,ou=groups,dc=example,dc=org", "Administrator"},
                    {"\"cognito:groups\":\"admins\"=\"Administrator\"",   "\"cognito:groups\"",         "admins",     "Administrator"},
                    {"groups:\" admins \"=Admin",                          "groups",                     " admins ",   "Admin"}, // spaces inside quotes are kept
                    {"groups:admins=\"a=b\"",                              "groups",                     "admins",     "a=b"},
                    {"groups:\"'admins'\"=Admin",                          "groups",                     "'admins'",   "Admin"}, // another quote inside double quotes
                    {"\"it's\":admins=Admin",                             "\"it's\"",                   "admins",     "Admin"},
                    {"groups:it's=Admin",                                  "groups",                     "it's",       "Admin"}, // an apostrophe that doesn't start the name
                    {"g:a=R",                                              "g",                          "a",          "R"}, // one-letter names
                    {NON_ASCII_PATH + ":" + NON_ASCII_TOKEN_ROLE + "=" + NON_ASCII_XNAT_ROLE,
                            NON_ASCII_PATH, NON_ASCII_TOKEN_ROLE, NON_ASCII_XNAT_ROLE}, // non-ASCII letters in every part
            };
        }

        @Parameter(0) public String entry;
        @Parameter(1) public String claimPath;
        @Parameter(2) public String tokenRole;
        @Parameter(3) public String xnatRole;

        @Test
        public void intoItsThreeParts() {
            final Parsed parsed = RoleSyncMapping.parse(entry);

            assertTrue(parsed.rejected().isEmpty());
            assertEquals(1, parsed.mappings().size());
            final RoleSyncMapping mapping = parsed.mappings().get(0);
            assertEquals(entry.trim(), mapping.entry);
            assertEquals(claimPath, mapping.claimPath);
            assertEquals(tokenRole, mapping.tokenRole);
            assertEquals(xnatRole, mapping.xnatRole);
        }
    }

    /** A whole setting: several entries, blank ones, and how a rejected entry is written. */
    public static class ParsesASetting {

        @Test
        public void findsNoEntriesInANullValue() {
            final Parsed parsed = RoleSyncMapping.parse(null);

            assertTrue(parsed.mappings().isEmpty());
            assertTrue(parsed.rejected().isEmpty());
        }

        @Test
        public void findsNoEntriesInABlankValue() {
            final Parsed parsed = RoleSyncMapping.parse(" , ,");

            assertTrue(parsed.mappings().isEmpty());
            assertTrue(parsed.rejected().isEmpty());
        }

        @Test
        public void findsNoEntriesInAnEmptyValue() {
            final Parsed parsed = RoleSyncMapping.parse("");

            assertTrue(parsed.mappings().isEmpty());
            assertTrue(parsed.rejected().isEmpty());
        }

        @Test
        public void findsNoEntriesInAValueOfOnlyCommas() {
            final Parsed parsed = RoleSyncMapping.parse(",,,");

            assertTrue(parsed.mappings().isEmpty());
            assertTrue(parsed.rejected().isEmpty());
        }

        @Test
        public void keepsEachEntryInTheOrderWrittenAndSkipsBlankOnes() {
            final Parsed parsed = RoleSyncMapping.parse("groups:admins=Administrator, ,admins=Admin,,roles:iq=XnatIQ,");

            assertEquals(Arrays.asList("groups:admins=Administrator", "roles:iq=XnatIQ"), entries(parsed.mappings()));
            assertEquals(List.of(new Rejected("admins=Admin", NO_COLON)), parsed.rejected());
        }

        @Test
        public void splitsTheClaimPathIntoSteps() {
            final RoleSyncMapping mapping = RoleSyncMapping.parse("resource_access.xnat.roles:xnat-admin=Administrator")
                                                           .mappings().get(0);

            assertArrayEquals(new String[] {"resource_access", "xnat", "roles"}, mapping.claimPathSteps());
        }

        @Test
        public void takesAQuotedClaimNameAsOneStep() {
            final RoleSyncMapping mapping = RoleSyncMapping.parse("\"cognito:groups\":admins=Administrator").mappings().get(0);

            assertArrayEquals(new String[] {"cognito:groups"}, mapping.claimPathSteps());
        }

        @Test
        public void takesAUrlClaimNameAsOneStep() {
            final RoleSyncMapping mapping =
                    RoleSyncMapping.parse("\"https://myapp.example.com/roles\":admin=Administrator").mappings().get(0);

            assertArrayEquals(new String[] {"https://myapp.example.com/roles"}, mapping.claimPathSteps());
        }

        @Test
        public void splitsAtDotsOutsideQuotesOnly() {
            final RoleSyncMapping mapping =
                    RoleSyncMapping.parse("resource_access.\"my.client\".roles:admin=Administrator").mappings().get(0);

            assertArrayEquals(new String[] {"resource_access", "my.client", "roles"}, mapping.claimPathSteps());
        }

        @Test
        public void takesEachQuotedClaimNameAsOneStep() {
            final RoleSyncMapping mapping = RoleSyncMapping
                    .parse("resource_access.\"my.client\".\"afsd.cdd\".roles:admin=Administrator").mappings().get(0);

            assertArrayEquals(new String[] {"resource_access", "my.client", "afsd.cdd", "roles"}, mapping.claimPathSteps());
        }

        @Test
        public void keepsACommaInsideQuotesInItsEntry() {
            final Parsed parsed = RoleSyncMapping.parse("groups:\"cn=admins,ou=groups\"=Administrator, roles:iq=XnatIQ");

            assertTrue(parsed.rejected().isEmpty());
            assertEquals(Arrays.asList("cn=admins,ou=groups", "iq"),
                         parsed.mappings().stream().map(mapping -> mapping.tokenRole).toList());
        }

        @Test
        public void rejectsEverythingAfterAQuoteThatIsNeverClosed() {
            // With the quote left open, the comma after it is inside the quotes, so the next entry is lost too.
            final Parsed parsed = RoleSyncMapping.parse("groups:\"admins=Administrator, roles:iq=XnatIQ");

            assertTrue(parsed.mappings().isEmpty());
            assertEquals(List.of(new Rejected("groups:\"admins=Administrator, roles:iq=XnatIQ", UNCLOSED_QUOTE)),
                         parsed.rejected());
        }

        @Test
        public void givesAOneStepClaimPathOneStep() {
            final RoleSyncMapping mapping = RoleSyncMapping.parse("groups:admins=Administrator").mappings().get(0);

            assertArrayEquals(new String[] {"groups"}, mapping.claimPathSteps());
        }

        @Test
        public void listsARepeatedEntryEachTimeItIsWritten() {
            final Parsed parsed = RoleSyncMapping.parse("admins=Admin, groups:admins=Administrator, admins=Admin, "
                    + "groups:admins=Administrator");

            assertEquals(2, parsed.mappings().size());
            assertEquals(Arrays.asList(new Rejected("admins=Admin", NO_COLON), new Rejected("admins=Admin", NO_COLON)),
                         parsed.rejected());
        }

        @Test(expected = UnsupportedOperationException.class)
        public void returnsMappingsThatCannotBeChanged() {
            RoleSyncMapping.parse("groups:admins=Administrator").mappings().clear();
        }

        @Test(expected = UnsupportedOperationException.class)
        public void returnsRejectionsThatCannotBeChanged() {
            RoleSyncMapping.parse("admins=Admin").rejected().clear();
        }

        @Test
        public void writesATabAsAnEscape() {
            final Parsed parsed = RoleSyncMapping.parse("groups:admins" + ch(0x0009) + "=Admin");

            assertEquals("groups:admins\\u0009=Admin", parsed.rejected().get(0).entry());
        }

        @Test
        public void writesAHiddenCharacterAsAnEscape() {
            final Parsed parsed = RoleSyncMapping.parse("groups:admins" + ch(0x00A0) + "=Admin");

            assertEquals("groups:admins\\u00A0=Admin", parsed.rejected().get(0).entry());
        }

        @Test
        public void writesAHiddenCharacterBeyond0xFFFFAsTwoEscapes() {
            final Parsed parsed = RoleSyncMapping.parse("groups:admins=Admin" + ch(0xE0020));

            assertEquals("groups:admins=Admin\\uDB40\\uDC20", parsed.rejected().get(0).entry());
        }

        @Test
        public void keepsVisibleCharactersBesideAHiddenOne() {
            final Parsed parsed = RoleSyncMapping.parse("r" + ch(0x00F4) + "les:" + ch(0x1F600) + ch(0x200B) + "=Admin");

            assertEquals("r" + ch(0x00F4) + "les:" + ch(0x1F600) + "\\u200B=Admin", parsed.rejected().get(0).entry());
        }

        private static List<String> entries(final List<RoleSyncMapping> mappings) {
            return mappings.stream().map(mapping -> mapping.entry).toList();
        }
    }
}
