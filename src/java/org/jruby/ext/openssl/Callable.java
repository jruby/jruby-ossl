package org.jruby.ext.openssl;

/**
 * Duplicate of java.util.concurrent.Callable, but pre-1.5.
 * 
 * @author nicksieger
 */
public interface Callable {
    Object call();
}
