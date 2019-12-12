package com.forticode.cipherise;

import java.security.PrivilegedActionException;

/**
 * Thrown by this SDK when an exceptional case occurs while interacting with the CS.
 * Errors can either be in the message or chained to this exception (the cause).
 */
public class CipheriseException extends Exception {
    final public int errorCode;

    /**
     * Constructs a new exception with {@code null} as its detail message.
     * The cause is not initialized, and may subsequently be initialized by a
     * call to {@link #initCause}.
     */
    public CipheriseException() {
        errorCode = 0;
    }

    /**
     * Constructs a new exception with the specified detail message.  The
     * cause is not initialized, and may subsequently be initialized by
     * a call to {@link #initCause}.
     *
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     */
    public CipheriseException(String message) {
        super(message);
        errorCode = 0;
    }

    /**
     * Constructs a new exception with the specified detail message and error code.
     * The cause is not initialized, and may subsequently be initialized by
     * a call to {@link #initCause}.
     *
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     * @param errorCode the error code.
     */
    public CipheriseException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructs a new exception with the specified cause and a detail
     * message of {@code (cause==null ? null : cause.toString())} (which
     * typically contains the class and detail message of {@code cause}).
     * This constructor is useful for exceptions that are little more than
     * wrappers for other throwables (for example, {@link
     * PrivilegedActionException}).
     *
     * @param cause the cause (which is saved for later retrieval by the
     *              {@link #getCause()} method).  (A {@code null} value is
     *              permitted, and indicates that the cause is nonexistent or
     *              unknown.)
     * @since 1.4
     */
    public CipheriseException(Throwable cause) {
        super(cause);
        errorCode = 0;
    }

    /**
     * Constructs a new exception with the specified detail message and
     * cause.  <p>Note that the detail message associated with
     * {@code cause} is <i>not</i> automatically incorporated in
     * this exception's detail message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method).  (A {@code null} value is
     *                permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     * @since 1.4
     */
    public CipheriseException(String message, Throwable cause) {
        super(message, cause);
        errorCode = 0;
    }

    @Override public String getMessage() {
        String message = super.getMessage();
        if (this.errorCode != 0) {
            message += " (" + Integer.toString(this.errorCode) + ")";
        }
        return message;
    }
}
