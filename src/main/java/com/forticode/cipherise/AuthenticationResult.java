package com.forticode.cipherise;

/**
 * Contains the result of the authentication.
 */
public class AuthenticationResult {
    final public Authenticated authenticated;
    final public String username;
    final public PayloadResponse payload;

    AuthenticationResult(Authenticated authenticated, String username, PayloadResponse payload) {
        this.authenticated = authenticated;
        this.username = username;
        this.payload = payload;
    }
}