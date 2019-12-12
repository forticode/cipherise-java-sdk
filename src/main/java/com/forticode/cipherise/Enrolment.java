package com.forticode.cipherise;

import org.json.JSONObject;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * An ongoing enrolment on a Forticode Cipherise server.
 */
public class Enrolment {
    static final String Header = "CiphEnrl";

    private final Service service;
    private final String logId;
    private final String username;
    private final String validateUrl;
    private final String WaveCodeUrl;
    private final String directEnrolUrl;
    private final String statusUrl;
    private String confirmationUrl;
    private String deviceId;
    private Map<Integer, PublicKey> publicKeys;

    /**
     * Constructs a new {@link Enrolment}. Not to be used directly; use
     * {@link Service#enrolUser(String)} to create a new session.
     *
     * @param service        The {@link Service} that this originated from.
     * @param username       The username of the user to enrol.
     * @param validateUrl    The URL of the validation endpoint; used to get the
     *                       binding result.
     * @param WaveCodeUrl    The URL of the WaveCode to display.
     * @param directEnrolUrl The URL of the direct enrolment, which is the contents of the WaveCode.
     * @param statusUrl      The URL of the status of the enrolment; can be queried
     *                       from client.
     */
    Enrolment(Service service, String logId, String username, String validateUrl, String WaveCodeUrl,
            String directEnrolUrl, String statusUrl, String confirmationUrl, String deviceId, Map<Integer, PublicKey> publicKeys) {
        this.service = service;
        this.logId = logId;
        this.username = username;
        this.validateUrl = validateUrl;
        this.WaveCodeUrl = WaveCodeUrl;
        this.directEnrolUrl = directEnrolUrl;
        this.statusUrl = statusUrl;
        this.publicKeys = publicKeys != null ? publicKeys : new HashMap<>();
        this.confirmationUrl = confirmationUrl;
        this.deviceId = deviceId;
    }

    /**
     * Presents a validation challenge for the user to confirm that the bound device
     * and their device are the same. This method will block until the user has
     * successfully bound at least one device to the session.
     *
     * @return The URL of an Identicon to be displayed, so that the user can
     *         visually compare it to the Identicon displayed on their device.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public String validate() throws CipheriseException {
        JSONObject res = this.service.get(this.validateUrl);
        this.confirmationUrl = res.getString("confirmationURL");
        this.deviceId = res.getString("deviceId");

        JSONObject publicKeysJSON = res.getJSONObject("publicKeys");
        for (String levelString : publicKeysJSON.keySet()) {
            this.publicKeys.put(Integer.valueOf(levelString),
                    CryptoUtil.getPublicKeyFromPKCS8(publicKeysJSON.getString(levelString)));
        }

        return res.getString("identiconURL");
    }

    /**
     * Completes the enrolment, and stores the resulting public key if available.
     *
     * @param valid Whether this enrolment is valid or not (i.e. whether the user
     *              confirmed that the Identicon displayed matches the Identicon
     *              shown on their device)
     * @return Whether or not the enrolment was successful
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public EnrolmentResult confirm(boolean valid) throws CipheriseException {
        return this.confirm(valid, null);
    }

    /**
     * Completes the enrolment, and stores the resulting public key if available.
     *
     * @param valid   Whether this enrolment is valid or not (i.e. whether the user
     *                confirmed that the Identicon displayed matches the Identicon
     *                shown on their device)
     * @param payload Optional payload request. For more information, consult the
     *                documentation for {@link PayloadRequest}.
     * @return Whether or not the enrolment was successful
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public EnrolmentResult confirm(boolean valid, PayloadRequest payload) throws CipheriseException {
        JSONObject body = new JSONObject();
        body.put("confirm", valid ? "confirm" : "reject");
        JSONObject serviceSignaturesJSON = new JSONObject();
        for (Map.Entry<Integer, PublicKey> entry : this.publicKeys.entrySet()) {
            byte[] serviceSignature = this.service.calculateSignature(this.username, this.deviceId,
                    CryptoUtil.getPKCS8FromPublicKey(entry.getValue()), entry.getKey().intValue());
            serviceSignaturesJSON.put(entry.getKey().toString(), CryptoUtil.toHexString(serviceSignature));
        }
        body.put("signatures", serviceSignaturesJSON);

        // Retrieve public key for level 1 for use in payload.
        PublicKey publicKey = this.publicKeys.get(1);

        // If payload has been requested, add it to the request.
        if (valid) {
            if (payload != null) {
                JSONObject payloadRequest = new JSONObject();
                payloadRequest.put("set", payload.set);
                body.put("payload", this.service.encryptPayloadData(publicKey, payloadRequest));
            }
        }

        JSONObject response = this.service.post(this.confirmationUrl, body);

        // If payload was requested, check if it was valid or not.
        PayloadResponse payloadResponse = null;
        if (valid && payload != null && response.has("payload")) {
            JSONObject payloadResponseJson = this.service.decryptPayloadJson(publicKey,
                    response.getJSONObject("payload"));
            boolean setResponse = payloadResponseJson.getBoolean("setResponse");
            valid = valid && setResponse;

            String payloadVerifyUrl = response.optString("payloadVerifyURL");
            if (payloadVerifyUrl != null && !payloadVerifyUrl.isEmpty()) {
                JSONObject verifyRequest = new JSONObject();
                verifyRequest.put("verified", valid);
                this.service.post(payloadVerifyUrl, verifyRequest);
            }

            payloadResponse = new PayloadResponse();
            payloadResponse.set = setResponse;
        }

        return new EnrolmentResult(valid, payloadResponse);
    }

    /**
     * @return The URL of the WaveCode to display.
     */
    public String getWaveCodeUrl() {
        return WaveCodeUrl;
    }

    /**
     * @return The URL used for direct enrolment.
     */
    public String getDirectEnrolUrl() {
        return this.directEnrolUrl;
    }

    /**
     * @return The URL of the status of the enrolment; can be queried from client.
     */
    public String getStatusUrl() {
        return this.statusUrl;
    }

    /**
     * Serializes this enrolment to a buffer that can be stored somewhere.
     * @return The serialized enrolment session as bytes.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public byte[] serialize() throws CipheriseException {
        try {
            MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
            // @formatter:off
            packer
                .packArrayHeader(11)
                .packString(Enrolment.Header)
                .packString(Client.SERIALIZED_VERSION)
                .packString(this.logId)
                .packString(this.WaveCodeUrl)
                .packString(this.directEnrolUrl)
                .packString(this.statusUrl)
                .packString(this.validateUrl)
                .packString(this.username);

            if (this.confirmationUrl != null) {
                packer.packString(this.confirmationUrl);
            } else {
                packer.packNil();
            }

            if (this.deviceId != null) {
                packer.packString(this.deviceId);
            } else {
                packer.packNil();
            }

            if (this.publicKeys != null) {
                packer.packMapHeader(this.publicKeys.size());
                for (Map.Entry<Integer, PublicKey> entry : this.publicKeys.entrySet()) {
                    packer.packString(entry.getKey().toString());
                    packer.packString(CryptoUtil.getPKCS8FromPublicKey(entry.getValue()));
                }
            } else {
                packer.packNil();
            }
            // @formatter:on
            packer.close();

            return packer.toByteArray();
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        try {
            Enrolment r = (Enrolment) o;

            // @formatter:off
            return
                (this.service != null ? this.service.equals(r.service) : true) &&
                (this.logId != null ? this.logId.equals(r.logId) : true) &&
                (this.username != null ? this.username.equals(r.username) : true) &&
                (this.validateUrl != null ? this.validateUrl.equals(r.validateUrl) : true) &&
                (this.WaveCodeUrl != null ? this.WaveCodeUrl.equals(r.WaveCodeUrl) : true) &&
                (this.directEnrolUrl != null ? this.directEnrolUrl.equals(r.directEnrolUrl) : true) &&
                (this.statusUrl != null ? this.statusUrl.equals(r.statusUrl) : true) &&
                (this.publicKeys != null ? this.publicKeys.equals(r.publicKeys) : true) &&
                (this.confirmationUrl != null ? this.confirmationUrl.equals(r.confirmationUrl) : true) &&
                (this.deviceId != null ? this.deviceId.equals(r.deviceId) : true);
            // @formatter:on
        } catch (ClassCastException e) {
            return false;
        }
    }
}
