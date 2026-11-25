package au.edu.qcif.xnat.auth.openid.bearer;

import au.edu.qcif.xnat.auth.openid.OpenIdAccountPolicy;
import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.OpenIdUserResolver;
import au.edu.qcif.xnat.auth.openid.gate.RoleSync;
import au.edu.qcif.xnat.auth.openid.jwt.JwtValidatorRegistry;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.authentication.AuthenticationEventPublisher;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * Covers the startup reporting itself, rather than the pattern analysis it delegates to.
 *
 * <p>These checks ran from the constructor until recently and said nothing on a deployment that had
 * something to report: XNAT applies a plugin's logging configuration part-way through initialisation,
 * after beans like this one exist, so a constructor-time log call goes to a logger inheriting the
 * server's {@code ERROR} root level and is discarded. They now run on context-refresh. Nothing asserted
 * on their output before, which is why that went unnoticed — so these capture it.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationFilterStartupTest {

    private static final String PROVIDER = "partner";
    private static final String SOURCE   = "directory";

    @Mock private OpenIdAuthPlugin plugin;
    @Mock private BearerProviderResolver providerResolver;

    private ListAppender<ILoggingEvent> appender;
    private Logger                      logger;
    private Level                       originalLevel;

    @Before
    public void capturePluginLogging() {
        logger = (Logger) LoggerFactory.getLogger(BearerTokenAuthenticationFilter.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.INFO);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        lenient().when(plugin.getProps()).thenReturn(new Properties());
    }

    @After
    public void restoreLogging() {
        logger.detachAppender(appender);
        logger.setLevel(originalLevel);
    }

    private List<String> messagesAt(final Level level) {
        return appender.list.stream()
                            .filter(event -> event.getLevel().equals(level))
                            .map(ILoggingEvent::getFormattedMessage)
                            .collect(Collectors.toList());
    }

    /** A filter built through the test seam, so only the reporting under test runs. */
    private BearerTokenAuthenticationFilter filter() {
        return new BearerTokenAuthenticationFilter(plugin, mock(BearerTokenExtractor.class),
                                                   providerResolver, new JwtValidatorRegistry(Collections.emptyMap()),
                                                   null, mock(OpenIdUserResolver.class),
                                                   mock(OpenIdAccountPolicy.class),
                                                   mock(AuthenticationEventPublisher.class));
    }

    /** The warnings role sync writes, through its own logger, while {@code action} runs. */
    private static List<String> roleSyncWarningsDuring(final Runnable action) {
        final Logger roleSyncLogger = (Logger) LoggerFactory.getLogger(RoleSync.class);
        final ListAppender<ILoggingEvent> captured = new ListAppender<>();
        captured.start();
        roleSyncLogger.addAppender(captured);
        try {
            action.run();
        } finally {
            roleSyncLogger.detachAppender(captured);
        }
        return captured.list.stream()
                            .filter(event -> event.getLevel().equals(Level.WARN))
                            .map(ILoggingEvent::getFormattedMessage)
                            .collect(Collectors.toList());
    }

    private void providers(final String... ids) {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList(ids));
    }

    private void property(final String providerId, final String name, final String value) {
        lenient().when(plugin.getProperty(providerId, name)).thenReturn(value);
    }

    private void linkingFrom(final String source) {
        property(PROVIDER, "linkExisting.enabled", "true");
        property(PROVIDER, "linkExisting.sourceProvider", source);
    }

    @Test
    public void saysNothingWhenLinkingIsNotEnabled() {
        providers(PROVIDER, SOURCE);

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue("an unconfigured provider has nothing to report", appender.list.isEmpty());
    }

    @Test
    public void theFilterXnatBuildsHasRoleSyncReportItsSettings() {
        // Role sync writes its own report; RoleSyncTest covers what it says.
        providers(PROVIDER);
        property(PROVIDER, "roleSync.enabled", "true");
        property(PROVIDER, "roleSync.mappings", "nocolon=Role");
        final BearerTokenAuthenticationFilter built = new BearerTokenAuthenticationFilter(plugin,
                mock(XdatUserAuthService.class), mock(SiteConfigPreferences.class),
                mock(AuthenticationEventPublisher.class), new JwtValidatorRegistry(Collections.emptyMap()),
                mock(Executor.class));

        final List<String> warnings = roleSyncWarningsDuring(() -> built.onApplicationEvent(mock(ContextRefreshedEvent.class)));

        assertTrue(warnings.toString(), warnings.stream().anyMatch(warning -> warning.contains("'nocolon=Role'")));
    }

    @Test
    public void reportsRoleSyncOnTheBearerPathForTheProvidersThisFilterServes() {
        providers(PROVIDER);
        property(PROVIDER, "roleSync.enabled", "true");
        property(PROVIDER, "roleSync.mappings", "nocolon=Role");
        lenient().when(providerResolver.providerIds()).thenReturn(Collections.singleton(PROVIDER));

        final List<String> warnings = roleSyncWarningsDuring(() -> filter().onApplicationEvent(mock(ContextRefreshedEvent.class)));

        assertTrue(warnings.toString(), warnings.stream().anyMatch(warning -> warning.contains("on the bearer path")));
    }

    @Test
    public void reportsLinkingEnabledWithNoSourceProvider() {
        providers(PROVIDER, SOURCE);
        property(PROVIDER, "linkExisting.enabled", "true");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue(messagesAt(Level.ERROR).stream().anyMatch(m -> m.contains("sets no")));
    }

    @Test
    public void namesAnUnconfiguredSourceProviderRatherThanBlamingItsDefaultPattern() {
        // usernamePatternOf falls back to the shipped default for a provider that does not exist, so the
        // pattern comparison would report [providerId] and send the operator after the wrong thing.
        providers(PROVIDER);
        linkingFrom("nosuchprovider");
        property(PROVIDER, "usernamePattern", "[upn]");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        final List<String> warnings = messagesAt(Level.WARN);
        assertTrue(warnings.stream().anyMatch(m -> m.contains("not a configured provider")));
        assertTrue("must not blame the default pattern",
                   warnings.stream().noneMatch(m -> m.contains("providerId")));
    }

    @Test
    public void reportsALocalDatabaseSourceAsUnmatchable() {
        // Only OpenID mappings are searched, so localdb can never match however well the claim lines up
        // with the account's username. It is a configured "provider", so the unconfigured-source check
        // does not catch it, and without this it would fail per request rather than at boot.
        providers(PROVIDER, SOURCE);
        linkingFrom("localdb");
        property(PROVIDER, "usernamePattern", "[upn]");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue(messagesAt(Level.WARN).stream()
                                         .anyMatch(m -> m.contains("only OpenID mappings are searched")));
    }

    @Test
    public void reportsAPatternThatCannotMatchAcrossProviders() {
        providers(PROVIDER, SOURCE);
        linkingFrom(SOURCE);
        property(PROVIDER, "usernamePattern", "[upn]");
        property(SOURCE, "usernamePattern", "[sub]");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue(messagesAt(Level.WARN).stream().anyMatch(m -> m.contains("'sub'")));
    }

    @Test
    public void notesDifferingPatternsWithoutWarning() {
        providers(PROVIDER, SOURCE);
        linkingFrom(SOURCE);
        property(PROVIDER, "usernamePattern", "[https://claims.example.org/upn]");
        property(SOURCE, "usernamePattern", "[preferred_username]");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue("differing names are a caution, not a defect", messagesAt(Level.WARN).isEmpty());
        assertTrue(messagesAt(Level.INFO).stream().anyMatch(m -> m.contains("verify that they do")));
    }

    @Test
    public void saysNothingWhenBothProvidersKeyOnTheSamePattern() {
        providers(PROVIDER, SOURCE);
        linkingFrom(SOURCE);
        property(PROVIDER, "usernamePattern", "[preferred_username]");
        property(SOURCE, "usernamePattern", "[preferred_username]");

        filter().onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue("a workable configuration must be silent", appender.list.isEmpty());
    }

    @Test
    public void reportsOnlyOnceAcrossRepeatedRefreshEvents() {
        // A parent/child context hierarchy refreshes more than once; the operator should not see the
        // same finding twice for that reason.
        providers(PROVIDER, SOURCE);
        linkingFrom(SOURCE);
        property(PROVIDER, "usernamePattern", "[upn]");
        property(SOURCE, "usernamePattern", "[sub]");

        final BearerTokenAuthenticationFilter filter = filter();
        filter.onApplicationEvent(mock(ContextRefreshedEvent.class));
        final int afterFirst = appender.list.size();
        filter.onApplicationEvent(mock(ContextRefreshedEvent.class));

        assertTrue("the first refresh must report something, or this proves nothing", afterFirst > 0);
        assertEquals("a second refresh must not repeat the findings", afterFirst, appender.list.size());
    }
}
