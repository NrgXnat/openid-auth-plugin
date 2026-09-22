package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.bearer.BearerTokenAuthenticationFilter;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.lang.reflect.Constructor;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

/**
 * Every {@code @Component} here is instantiated by Spring, which picks the constructor itself. It only
 * does that without an explicit {@link Autowired} when the class declares exactly one; give a class a
 * second constructor and Spring stops choosing, falls back to a no-arg constructor that does not exist,
 * and the bean fails to construct. A filter that fails to construct takes the whole XNAT context down —
 * every URL 404s, not just this plugin's.
 *
 * <p>Nothing else catches this. The Spring fixtures in this suite build these filters with an explicit
 * {@code new} in a {@code @Bean} method, so constructor selection never happens; the first time it does
 * is at startup on a real server.</p>
 */
public class ComponentConstructorInjectionTest {

    @Test
    public void openIdConnectFilterDeclaresWhichConstructorSpringShouldUse() {
        assertUnambiguous(OpenIdConnectFilter.class);
    }

    @Test
    public void bearerTokenAuthenticationFilterDeclaresWhichConstructorSpringShouldUse() {
        assertUnambiguous(BearerTokenAuthenticationFilter.class);
    }

    /**
     * Asserts that Spring has exactly one constructor to choose for {@code type}: either the class
     * declares one, or one of them is annotated.
     */
    private static void assertUnambiguous(final Class<?> type) {
        final Constructor<?>[] declared = type.getDeclaredConstructors();
        if (declared.length == 1) {
            return;
        }
        final long annotated = Arrays.stream(declared).filter(c -> c.isAnnotationPresent(Autowired.class)).count();
        assertEquals(type.getSimpleName() + " declares " + declared.length + " constructors, so exactly one must "
                     + "carry @Autowired for Spring to instantiate it", 1, annotated);
    }
}
