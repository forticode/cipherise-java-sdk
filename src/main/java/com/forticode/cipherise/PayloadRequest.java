package com.forticode.cipherise;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Used to request that the device conduct some payload-relevant action. It is
 * supplied as part of payload-enabled operations.
 *
 * During certain payload-enabled operations, the device can store or retrieve
 * data that has been provided by the Service Provider. This is the "payload"
 * functionality.
 *
 * Additional fields may be added to this class when more payload actions are
 * made available.
 *
 * Not all actions are available during payload-enabled operations. As an
 * example, the `get` operation will not work during enrolment as there is no
 * data to retrieve.
 */
public class PayloadRequest {
    /**
     * An array of identifiers for data to retrieve from the device.
     */
    public List<String> get = new ArrayList<>();
    /**
     * A dictionary of (identifier, data) to store on the device.
     */
    public Map<String, String> set = new HashMap<>();
}