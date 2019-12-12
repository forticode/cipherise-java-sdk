package com.forticode.cipherise;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.Iterator;

/**
 * An ongoing authentication on a Forticode Cipherise server.
 */
public class Authentication {
    final static String WaveHeader = "CiphUsrW";
    final static String PushHeader = "CiphUsrP";

    final private Service service;
    private String username = null;
    private Device device = null;
    private String verifyAuthenticationURL = null;

    final private String authMode;
    final private String logId;
    final private AuthenticationLevel authLevel;
    final private String appAuthenticationURL;
    final private String WaveCodeURL;
    final private String directURL;
    final private String challengeExchangeURL;
    final private String statusURL;

    /**
     * Constructs a new {@link Authentication}.
     *
     * @param service              The {@link Service} that this originated from.
     * @param authMode             The type of authentication that started this.
     *                             Either 'Push' or 'Wave'.
     * @param logId                The log identifier for this authentication.
     * @param authLevel            The level of challenge requested. Valid values
     *                             are 1-4.
     * @param appAuthenticationURL An endpoint at the Cipherise Server where the
     *                             Service Provider can retrieve the Application's
     *                             authentication challenge.
     * @param WaveCodeURL          A URL to the WaveCode that this Service Provider
     *                             should display for the purposes of the
     *                             authentication.
     * @param directURL            A URL to the link within the WaveCode, the Service
     *                             Providers authentication challenge.
     * @param challengeExchangeURL A URL to place the solution to the challenge
     *                             issued by the Application.
     * @param statusURL            A URL to retrieve the state of the Authentication
     *                             process. Primarily used in a short poll process.
     * @param username             The username that the Authentication was started
     *                             with. Only applicable in PushAuth authentications.
     * @param device               The device identifier of the device this
     *                             Authentication was sent to. Only applicable in
     *                             PushAuth authentications.
     * @param verifyAuthenticationURL Optional verification URL.
     */
    Authentication(Service service, String authMode, String logId, AuthenticationLevel authLevel,
                   String appAuthenticationURL, String WaveCodeURL, String directURL, String challengeExchangeURL, String statusURL,
                   String username, Device device, String verifyAuthenticationURL) {
        this.service = service;
        this.authMode = authMode;
        this.logId = logId;
        this.authLevel = authLevel;
        this.username = username;
        this.device = device;
        this.appAuthenticationURL = appAuthenticationURL;
        this.WaveCodeURL = WaveCodeURL;
        this.directURL = directURL;
        this.challengeExchangeURL = challengeExchangeURL;
        this.statusURL = statusURL;
        this.verifyAuthenticationURL = verifyAuthenticationURL;
    }

    /**
     *
     * @return The URL to the WaveCode to display for this authentication. May be
     *         null if not relevant.
     */
    public String getWaveCodeUrl() {
        return this.WaveCodeURL;
    }

    /**
     * @return The URL used for direct authentication. May be null if not relevant.
     */
    public String getDirectAuthUrl() {
        return this.directURL;
    }

    /**
     * @return The log identifier for this authentication.
     */
    public String getLogId() {
        return this.logId;
    }

    // TODO: Status

    /**
     * Once this authentication session has been set up, this function will complete
     * the authentication process. Note that this function is blocking.
     * Automatically accepts the authentication.
     *
     * @return A Boolean indication of the success or failure of the authentication.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public AuthenticationResult authenticate() throws CipheriseException {
        return this.authenticate(true);
    }

    /**
     * Once this authentication session has been set up, this function will complete
     * the authentication process. Note that this function is blocking.
     *
     * @param autoAccept Whether or not to auto-accept the authentication. See
     *                   {@link Authentication#accept(Boolean, String)} for more
     *                   information.
     *
     * @return AuthenticationResult
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public AuthenticationResult authenticate(boolean autoAccept) throws CipheriseException {
        return this.authenticate(autoAccept, null);
    }

    /**
     * Once this authentication session has been set up, this function will complete
     * the authentication process. Note that this function is blocking.
     *
     * @param autoAccept Whether or not to auto-accept the authentication. See
     *                   {@link Authentication#accept(Boolean, String)} for more
     *                   information.
     * @param payload    Optional payload request. For more information, consult the
     *                   documentation for {@link PayloadRequest}.
     * @return AuthenticationResult
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public AuthenticationResult authenticate(boolean autoAccept, PayloadRequest payload) throws CipheriseException {
        // Start by waiting for App challenge
        JSONObject appChallengeResponse = this.service.get(this.appAuthenticationURL);

        // If push auth, confirm username
        if (authMode.equals("Push")) {
            if (!username.equals(appChallengeResponse.getString("username"))) {
                throw new CipheriseException("Incorrect username information returned - ours = " + username
                        + " servers = " + appChallengeResponse.getString("username"));
            }
        } else {
            this.username = appChallengeResponse.getString("username");
        }

        // Then solve challenge, and issue our own
        byte[] appSolution = this.service
                .sign(CryptoUtil.fromHexString(appChallengeResponse.getString("appChallenge")));

        // Generate an auth challenge
        byte[] userAuthChallenge = CryptoUtil.generateRandomBytes(16);

        JSONObject body = new JSONObject();
        body.put("appChallengeSolution", CryptoUtil.toHexString(appSolution));
        body.put("authenticationLevel", this.authLevel.level);
        body.put("authenticationChallenge", CryptoUtil.toHexString(userAuthChallenge));
        body.put("waitForAppSolution", true);

        // Submit the solution to the CS and retrieve the result.
        JSONObject assertion = this.service.post(this.challengeExchangeURL, body);

        // Finally, verify signatures and return result
        String authenticated = assertion.getString("authenticated");
        int publicKeyLevel = assertion.getInt("publicKeyLevel");
        String deviceId = assertion.getString("deviceId");
        this.verifyAuthenticationURL = assertion.getString("verifyAuthenticationURL");

        Boolean verified = false;
        boolean payloadValid = true;
        PayloadResponse payloadResponse = new PayloadResponse();
        try {
            // Reject the response early if the status is inappropriate.
            if (authenticated.equals("cancelled")) {
                return new AuthenticationResult(Authenticated.Cancel, username, payloadResponse);
            } else if (authenticated.equals("reported")) {
                return new AuthenticationResult(Authenticated.Report, username, payloadResponse);
            } else if (!authenticated.equals("true")) {
                return new AuthenticationResult(Authenticated.Failure, username, payloadResponse);
            }

            // Get the public key from the response. Note that this can't be retrieved from
            // the device public keys +
            // level; the phone is allowed to promote auth levels as appropriate, so this
            // public key may not be the one
            // that was initially used.
            PublicKey publicKey = CryptoUtil.getPublicKeyFromPKCS8(assertion.getString("publicKey"));

            // Reconstruct the binding signature, and ensure it matches with the one the
            // server gives us
            byte[] deviceSignature = Hex.decode(assertion.getString("keySignature"));
            byte[] ourSignature = this.service.calculateSignature(this.username, deviceId,
                    assertion.getString("publicKey"), publicKeyLevel);

            if (!Arrays.equals(deviceSignature, ourSignature)) {
                throw new CipheriseException(
                        "Server returned invalid signature for user authentication of " + this.username);
            }

            // Verify the solution, and return success/failure
            String userAuthChallengeSolution = assertion.getString("authenticationSolution");
            Signature signature;
            try {
                signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(userAuthChallenge);
                verified = signature.verify(Hex.decode(userAuthChallengeSolution));
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new CipheriseException(e);
            }

            if (payload != null) {
                JSONObject payloadRequestData = new JSONObject();
                payloadRequestData.put("get", payload.get);
                payloadRequestData.put("set", payload.set);

                JSONObject payloadRequest = new JSONObject();
                payloadRequest.put("payload", this.service.encryptPayloadData(publicKey, payloadRequestData));
                JSONObject payloadRequestEncrypted = this.service.post(assertion.getString("payloadURL"),
                        payloadRequest);
                JSONObject payloadResponseJson = this.service.decryptPayloadJson(publicKey,
                        payloadRequestEncrypted.getJSONObject("payload"));

                if (!payload.set.isEmpty()) {
                    payloadResponse.set = payloadResponseJson.getBoolean("setResponse");
                }

                JSONObject getResponse = payloadResponseJson.getJSONObject("getResponse");
                Iterator<String> keysItr = getResponse.keys();
                while (keysItr.hasNext()) {
                    String key = keysItr.next();
                    payloadResponse.get.put(key, getResponse.getString(key));
                }

                payloadValid = payload.set.isEmpty() || payloadResponse.set;
            }

            Authenticated result = verified ? Authenticated.Success : Authenticated.Failure;
            return new AuthenticationResult(result, username, payloadResponse);
        } finally {
            if (autoAccept) {
                this.accept(verified && payloadValid, null);
            }
        }
    }

    /**
     * Notifies the app as to whether an authentication succeeded or failed. This is
     * called by authenticate automatically unless autoAccept = false is specified.
     *
     * Can be used to inform the app that the authentication has failed for other
     * reasons (e.g. failed authorization).
     *
     * @param accepted   Whether or not the authentication has been accepted.
     * @param failReason The reason that the authentication failed.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public void accept(Boolean accepted, String failReason) throws CipheriseException {
        if (this.verifyAuthenticationURL == null) {
            throw new CipheriseException("Expected authentication verification URL. Has `authenticate` been called?");
        }

        JSONObject body = new JSONObject();
        body.put("verified", accepted);
        body.put("failReason", failReason);

        this.service.post(this.verifyAuthenticationURL, body);
    }

    /**
     * Serializes this authentication to a buffer that can be stored somewhere. Use
     * this to store a created {@link Authentication} for use at a later stage.
     * @return The serialized buffer.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public byte[] serialize() throws CipheriseException {
        try {
            if (this.authMode.equals("Push")) {
                byte[] serializedDevice = this.device.serialize();

                // As the challenge is generated dynamically in the Java SDK,
                // we marshal a challenge of 0 bytes.
                byte[] challenge = new byte[0];

                MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
                // @formatter:off
                packer
                    .packArrayHeader(11)
                    .packString(Authentication.PushHeader)
                    .packString(Client.SERIALIZED_VERSION)
                    .packString(this.logId)
                    .packBinaryHeader(challenge.length)
                    .writePayload(challenge)
                    .packInt(this.authLevel.level)
                    .packString(this.username)
                    .packBinaryHeader(serializedDevice.length)
                    .writePayload(serializedDevice)
                    .packString(this.statusURL)
                    .packString(this.challengeExchangeURL)
                    .packString(this.appAuthenticationURL);

                if (this.verifyAuthenticationURL != null) {
                    packer.packString(this.verifyAuthenticationURL);
                } else {
                    packer.packNil();
                }
                // @formatter:on
                packer.close();

                return packer.toByteArray();
            } else if (this.authMode.equals("Wave")) {
                // As the challenge is generated dynamically in the Java SDK,
                // we marshal a challenge of 0 bytes.
                byte[] challenge = new byte[0];

                MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
                // @formatter:off
                packer
                    .packArrayHeader(11)
                    .packString(Authentication.WaveHeader)
                    .packString(Client.SERIALIZED_VERSION)
                    .packString(this.logId)
                    .packBinaryHeader(challenge.length)
                    .writePayload(challenge)
                    .packInt(this.authLevel.level)
                    .packString(this.directURL)
                    .packString(this.WaveCodeURL)
                    .packString(this.statusURL)
                    .packString(this.appAuthenticationURL)
                    .packString(this.challengeExchangeURL);

                if (this.verifyAuthenticationURL != null) {
                    packer.packString(this.verifyAuthenticationURL);
                } else {
                    packer.packNil();
                }
                // @formatter:on
                packer.close();

                return packer.toByteArray();
            } else {
                throw new CipheriseException("Unsupported authentication mode.");
            }
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        try {
            Authentication r = (Authentication) o;

            // @formatter:off
            return
                (this.service != null ? this.service.equals(r.service) : true) &&
                (this.authMode != null ? this.authMode.equals(r.authMode) : true) &&
                (this.logId != null ? this.logId.equals(r.logId) : true) &&
                (this.authLevel != null ? this.authLevel.equals(r.authLevel) : true) &&
                (this.username != null ? this.username.equals(r.username) : true) &&
                (this.device != null ? this.device.equals(r.device) : true) &&
                (this.appAuthenticationURL != null ? this.appAuthenticationURL.equals(r.appAuthenticationURL) : true) &&
                (this.WaveCodeURL != null ? this.WaveCodeURL.equals(r.WaveCodeURL) : true) &&
                (this.directURL != null ? this.directURL.equals(r.directURL) : true) &&
                (this.challengeExchangeURL != null ? this.challengeExchangeURL.equals(r.challengeExchangeURL) : true) &&
                (this.statusURL != null ? this.statusURL.equals(r.statusURL) : true);
            // @formatter:on
        } catch (ClassCastException e) {
            return false;
        }
    }
}
