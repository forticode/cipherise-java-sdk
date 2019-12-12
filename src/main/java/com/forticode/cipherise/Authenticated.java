package com.forticode.cipherise;

/**
 * The user's response at the conclusion of the authentication.
 */
public enum Authenticated {
    /**
     * Indicates that the authentication was successful.
     */
    Success,
    /**
     * Indicates that the authentication was cancelled by the Cipherise application user.
     */
    Cancel,
    /**
     * Indicates that the authentication failed. This could happen due to an error in solving the
     * OneTiCK challenge, network issues or a mismatch in the validation of the users device.
     */
    Failure,
    /**
     * Indicates that the Cipherise application user has reported the authentication, cancelling the
     * authentication and informing the Cipherise Server that followup action should be taken.
     */
    Report
}