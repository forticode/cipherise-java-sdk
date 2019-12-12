package com.forticode.cipherise;

public class EnrolmentResult {
    final public Boolean success;
    final public PayloadResponse payload;

    EnrolmentResult(Boolean success, PayloadResponse payload) {
        this.success = success;
        this.payload = payload;
    }
}