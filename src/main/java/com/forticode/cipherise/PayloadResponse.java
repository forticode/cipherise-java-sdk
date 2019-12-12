package com.forticode.cipherise;

import java.util.HashMap;
import java.util.Map;

/**
 * Returned when a payload action, or a set thereof, has concluded.
 */
public class PayloadResponse {
    /**
     * A dictionary of (identifier, data) retrieved from the device. Empty if no
     * data was requested.
     */
    public Map<String, String> get = new HashMap<>();

    /**
     * Whether or not the set action was successful. False if a set action was not
     * requested.
     */
    public boolean set = false;
}
