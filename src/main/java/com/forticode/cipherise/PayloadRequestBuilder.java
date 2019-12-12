package com.forticode.cipherise;

import java.util.List;
import java.util.Map;

/**
 * Helper class to ease construction of payload requests.
 */
public class PayloadRequestBuilder {
    private PayloadRequest pr = new PayloadRequest();

    public PayloadRequestBuilder withGet(List<String> get) {
        this.pr.get = get;
        return this;
    }

    public PayloadRequestBuilder withSet(Map<String, String> set) {
        this.pr.set = set;
        return this;
    }

    /**
     * Get the constructed payload request.
     * @return The PayloadRequest.
     */
    public PayloadRequest build() {
        return this.pr;
    }
}
