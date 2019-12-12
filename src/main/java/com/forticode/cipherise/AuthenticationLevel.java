package com.forticode.cipherise;

/**
 * The "level" of an authentication. The higher it is, the stronger the
 * guarantee of user identity; however, this will require a correspondingly
 * higher level of effort on the user's part.
 */
public enum AuthenticationLevel {
    /**
     * Cipherise challenge level 1 - The least intrusive authentication method. Only requires the
     * Cipherise application to be open for authentication challenge to be solved.
     */
    Notification(1),
    /**
     * Cipherise challenge level 2 - Interaction by user required in the Cipherise application to
     * approve, cancel or report.
     */
    Approval(2),
    /**
     * Cipherise challenge level 3 - Interaction by user required in the Cipherise application to
     * apply a biometric input (finger print or face), or cancel or report. Note that if the device
     * the Cipherise application is running on does not have the necessary hardware or it is
     * disabled, this will be elevated to a OneTiCK challenge.
     */
    Biometric(3),
    /**
     * Cipherise challenge level 4 - Interaction by user required in the Cipherise application to
     * solve the OneTiCK (One Time Cognitive Keyboard) challenge, or cancel or report.
     */
    OneTiCK(4);

    final int level;

    private AuthenticationLevel(int level) {
        this.level = level;
    }

    static AuthenticationLevel fromLevel(int level) {
        for (AuthenticationLevel al : AuthenticationLevel.values()) {
            if (al.level == level) {
                return al;
            }
        }

        return null;
    }
}
