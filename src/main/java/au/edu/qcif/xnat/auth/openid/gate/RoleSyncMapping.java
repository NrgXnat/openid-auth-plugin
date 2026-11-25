package au.edu.qcif.xnat.auth.openid.gate;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * One entry of the {@code roleSync.mappings} setting, {@code <claim path>:<token role>=<XNAT role>}, for
 * example {@code resource_access.xnat.roles:xnat-admin=Administrator}.
 *
 * <p>Entries are separated by commas. An entry is cut at its first {@code :} and its last {@code =}, and its
 * claim path is a list of claim names separated by {@code .}. A name wrapped in double quotes is taken as
 * written, and a separator inside the quotes doesn't count, so any name can be mapped:</p>
 * <pre>
 * "cognito:groups":admins=Administrator
 * resource_access."my.client".roles:admin=Administrator
 * groups:"cn=admins,ou=groups,dc=example,dc=org"=Administrator
 * </pre>
 *
 * <p>Outside quotes, the token role and the XNAT role may hold a {@code :} but not a {@code =} or a
 * {@code ,}, and a claim name can't hold a space or be empty, as no real claim name does. Whitespace around
 * an entry and ordinary spaces around each part are ignored. Anywhere, a control character, a formatting
 * character such as a zero-width space, or any space but the ordinary one makes the entry malformed.</p>
 *
 * <p>Only the entry's shape is checked here, not whether XNAT defines the XNAT role.</p>
 */
final class RoleSyncMapping {

    /** Why an entry was rejected. Each text ends a warning such as "... ignores the mapping 'x': it has ...". */
    enum Reason {
        HIDDEN_CHARACTER("holds a hidden character, shown as \\uXXXX"),
        UNCLOSED_QUOTE("has a '\"' that is never closed"),
        NO_COLON("has no ':' after its claim path"),
        NO_EQUALS("has no '=' after its token role"),
        NO_CLAIM_PATH("has nothing before its ':'"),
        EMPTY_PATH_STEP("has an empty step in its claim path, such as 'a..b'"),
        MISPLACED_QUOTE("has a '\"' that doesn't wrap a whole name, as in '\"cognito:groups\"'"),
        WRONG_QUOTE("starts a name with a quote other than '\"'; only a straight double quote takes a name as written"),
        SPACE_IN_CLAIM_PATH("has a space in its claim path, outside double quotes"),
        NO_TOKEN_ROLE("has nothing between its ':' and its '='"),
        URL_CLAIM_NAME("has a claim name holding ':', such as a URL, outside double quotes"),
        EQUALS_IN_TOKEN_ROLE("has a '=' in its token role, outside double quotes"),
        NO_XNAT_ROLE("has nothing after its '='");

        final String text;

        Reason(final String text) {
            this.text = text;
        }
    }

    /** An entry that didn't parse, written so that any hidden character shows as a backslash-u escape. */
    record Rejected(String entry, Reason reason) {
    }

    /** The entries of a setting: those that parsed and those that didn't, each in the order written. */
    record Parsed(List<RoleSyncMapping> mappings, List<Rejected> rejected) {
    }

    /** The entry as written, trimmed. */
    final String entry;
    /** The claim path as written, with any quotes; {@link #claimPathSteps} gives the names to follow. */
    final String claimPath;
    /** The token role, without any quotes around it. */
    final String tokenRole;
    /** The XNAT role, without any quotes around it. */
    final String xnatRole;

    /** Cuts {@code entry} into its parts; call only once {@link #problemWith} has passed it. */
    private RoleSyncMapping(final String entry) {
        final String[] parts = cut(entry);
        this.entry = entry;
        this.claimPath = parts[0];
        this.tokenRole = unquote(parts[1]);
        this.xnatRole = unquote(parts[2]);
    }

    /** The claim path split into the names to follow through the token's claims, without their quotes. */
    String[] claimPathSteps() {
        return splitOutsideQuotes(claimPath, '.').stream().map(RoleSyncMapping::unquote).toArray(String[]::new);
    }

    /** Parses a {@code roleSync.mappings} value; a null or blank value has no entries. */
    static Parsed parse(final String value) {
        final List<RoleSyncMapping> mappings = new ArrayList<>();
        final List<Rejected> rejected = new ArrayList<>();
        if (value != null) {
            for (final String raw : splitOutsideQuotes(value, ',')) {
                final String entry = raw.trim();
                if (entry.isEmpty()) {
                    continue;
                }
                final Reason problem = problemWith(entry);
                if (problem == null) {
                    mappings.add(new RoleSyncMapping(entry));
                } else {
                    rejected.add(new Rejected(escapeHidden(entry), problem));
                }
            }
        }
        return new Parsed(List.copyOf(mappings), List.copyOf(rejected));
    }

    /**
     * Why {@code entry} can't be used, or null when it can. The checks run in a fixed order: hidden
     * characters and quotes left open first, so the later ones see only visible text with every quote closed;
     * then the entry's shape; then its claim path, token role, and XNAT role.
     */
    private static Reason problemWith(final String entry) {
        if (entry.codePoints().anyMatch(RoleSyncMapping::isHidden)) {
            return Reason.HIDDEN_CHARACTER;
        }
        if (entry.chars().filter(character -> character == '"').count() % 2 == 1) {
            return Reason.UNCLOSED_QUOTE;
        }
        final int colon = firstOutsideQuotes(entry, ':');
        if (colon < 0) {
            return Reason.NO_COLON;
        }
        if (lastOutsideQuotes(entry, '=') < colon) {
            return Reason.NO_EQUALS;
        }
        final String[] parts = cut(entry);
        Reason problem = claimPathProblem(parts[0]);
        if (problem == null) {
            problem = tokenRoleProblem(parts[1]);
        }
        if (problem == null) {
            problem = xnatRoleProblem(parts[2]);
        }
        return problem;
    }

    private static Reason claimPathProblem(final String claimPath) {
        if (claimPath.isEmpty()) {
            return Reason.NO_CLAIM_PATH;
        }
        final List<String> steps = splitOutsideQuotes(claimPath, '.');
        if (steps.stream().anyMatch(RoleSyncMapping::isEmptyName)) {
            return Reason.EMPTY_PATH_STEP;
        }
        final Reason quoteProblem =
                steps.stream().map(RoleSyncMapping::quoteProblem).filter(Objects::nonNull).findFirst().orElse(null);
        if (quoteProblem != null) {
            return quoteProblem;
        }
        return steps.stream().anyMatch(step -> !isQuoted(step) && step.indexOf(' ') >= 0)
                ? Reason.SPACE_IN_CLAIM_PATH : null;
    }

    private static Reason tokenRoleProblem(final String tokenRole) {
        if (isEmptyName(tokenRole)) {
            return Reason.NO_TOKEN_ROLE;
        }
        if (isQuoted(tokenRole)) {
            return null;
        }
        final Reason quoteProblem = quoteProblem(tokenRole);
        if (quoteProblem != null) {
            return quoteProblem;
        }
        if (tokenRole.startsWith("//")) {
            return Reason.URL_CLAIM_NAME;
        }
        return tokenRole.contains("=") ? Reason.EQUALS_IN_TOKEN_ROLE : null;
    }

    private static Reason xnatRoleProblem(final String xnatRole) {
        return isEmptyName(xnatRole) ? Reason.NO_XNAT_ROLE : quoteProblem(xnatRole);
    }

    /** What is wrong with the quotes of a name that isn't empty, or null; nothing when quotes wrap it whole. */
    private static Reason quoteProblem(final String name) {
        if (isQuoted(name)) {
            return null;
        }
        if (name.indexOf('"') >= 0) {
            return Reason.MISPLACED_QUOTE;
        }
        return isOtherQuote(name.codePointAt(0)) ? Reason.WRONG_QUOTE : null;
    }

    /** The claim path, token role, and XNAT role of {@code entry}, each trimmed and with any quotes kept. */
    private static String[] cut(final String entry) {
        final int colon = firstOutsideQuotes(entry, ':');
        final int equals = lastOutsideQuotes(entry, '=');
        return new String[] {
                entry.substring(0, colon).trim(),
                entry.substring(colon + 1, equals).trim(),
                entry.substring(equals + 1).trim()
        };
    }

    private static int firstOutsideQuotes(final String text, final char wanted) {
        final List<Integer> indexes = indexesOutsideQuotes(text, wanted);
        return indexes.isEmpty() ? -1 : indexes.get(0);
    }

    private static int lastOutsideQuotes(final String text, final char wanted) {
        final List<Integer> indexes = indexesOutsideQuotes(text, wanted);
        return indexes.isEmpty() ? -1 : indexes.get(indexes.size() - 1);
    }

    /** {@code text} split at each {@code separator} that is outside double quotes; quotes are kept. */
    private static List<String> splitOutsideQuotes(final String text, final char separator) {
        final List<String> pieces = new ArrayList<>();
        int start = 0;
        for (final int index : indexesOutsideQuotes(text, separator)) {
            pieces.add(text.substring(start, index));
            start = index + 1;
        }
        pieces.add(text.substring(start));
        return pieces;
    }

    /** Where {@code wanted} occurs in {@code text} outside double quotes. */
    private static List<Integer> indexesOutsideQuotes(final String text, final char wanted) {
        final List<Integer> indexes = new ArrayList<>();
        boolean quoted = false;
        for (int index = 0; index < text.length(); index++) {
            final char character = text.charAt(index);
            if (character == '"') {
                quoted = !quoted;
            } else if (character == wanted && !quoted) {
                indexes.add(index);
            }
        }
        return indexes;
    }

    /** True for a name that is blank, or is nothing but a pair of quotes. */
    private static boolean isEmptyName(final String name) {
        return name.isBlank() || name.equals("\"\"");
    }

    /** True for a name wrapped whole in double quotes, with none inside. */
    private static boolean isQuoted(final String name) {
        return name.length() >= 2 && name.startsWith("\"") && name.indexOf('"', 1) == name.length() - 1;
    }

    private static String unquote(final String name) {
        return isQuoted(name) ? name.substring(1, name.length() - 1) : name;
    }

    /**
     * True for a quote that isn't the straight double one: a single quote, a backtick, or a typographic quote
     * such as the curly ones a word processor puts in.
     */
    private static boolean isOtherQuote(final int codePoint) {
        final int type = Character.getType(codePoint);
        return codePoint == '\'' || codePoint == '`' || codePoint == 0x201A || codePoint == 0x201E
                || type == Character.INITIAL_QUOTE_PUNCTUATION || type == Character.FINAL_QUOTE_PUNCTUATION;
    }

    /**
     * True for a character a mapping may not hold: a control character, a formatting character such as a
     * zero-width space, or any space but the ordinary one.
     */
    private static boolean isHidden(final int codePoint) {
        return Character.isISOControl(codePoint) || Character.getType(codePoint) == Character.FORMAT
                || (Character.isSpaceChar(codePoint) && codePoint != ' ');
    }

    /** {@code value} with each hidden character written as a backslash-u escape, one per UTF-16 unit. */
    static String escapeHidden(final String value) {
        final StringBuilder out = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            if (isHidden(codePoint)) {
                for (final char unit : Character.toChars(codePoint)) {
                    out.append(String.format("\\u%04X", (int) unit));
                }
            } else {
                out.appendCodePoint(codePoint);
            }
        });
        return out.toString();
    }
}
