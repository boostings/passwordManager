package pm.crypto;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Types whose instances {@code SafeLog} refuses to log (SR-500, FIO13-J). {@link Inherited}, so a
 * subclass of a sensitive class is sensitive too.
 */
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface Sensitive {
}
