package com.forticode.cipherise;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.core.MessageBufferPacker;

/**
 * Service provider on a Forticode Cipherise server.
 */
public class Service {
    final static String Header = "CiphSrvc";

    final private Client client;
    final private WebClient webClient;
    final private String serviceId;
    final private PrivateKey privateKey;
    private String sessionId;

    /**
     * Constructs a new {@link Service}. Not to be used directly; use {@link Client}
     * methods to construct a {@link Service}.
     *
     * @param client     The {@link Client} being used to interface with the
     *                   Cipherise server.
     * @param webClient  The web client used to make requests.
     * @param serviceId  This Service Provider's identifier, as provided by the
     *                   Cipherise server.
     * @param privateKey The private key for this service provider, as generated by
     *                   the Client.
     */
    Service(Client client, WebClient webClient, String serviceId, PrivateKey privateKey) {
        this(client, webClient, serviceId, privateKey, "");
    }

    /**
     * Constructs a new {@link Service}. Not to be used directly; use {@link Client}
     * methods to construct a {@link Service}.
     *
     * @param client     The {@link Client} being used to interface with the
     *                   Cipherise server.
     * @param webClient  The web client used to make requests.
     * @param serviceId  This Service Provider's identifier, as provided by the
     *                   Cipherise server.
     * @param privateKey The private key for this service provider, as generated by
     *                   the Client.
     * @param sessionId  The session id.
     */
    Service(Client client, WebClient webClient, String serviceId, PrivateKey privateKey, String sessionId) {
        this.client = client;
        this.webClient = webClient;
        this.serviceId = serviceId;
        this.privateKey = privateKey;
        this.sessionId = sessionId;
    }

    /**
     * @return The identifier associated with this Service Provider.
     */
    public String getId() {
        return this.serviceId;
    }

    /**
     * Sign data with our private key.
     */
    byte[] sign(byte[] nonce) {
        byte[] resultBuffer = null;
        try {
            // Sign the nonce with our private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(this.privateKey);
            signature.update(nonce);
            resultBuffer = signature.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        return resultBuffer;
    }

    JSONObject get(String path) throws CipheriseException {
        for (int i = 0; i < 2; ++i) {
            try {
                return this.webClient.get(path, this.sessionId);
            } catch (CipheriseException e) {
                if (e.errorCode == 42) {
                    this.authenticate();
                    continue;
                } else {
                    throw e;
                }
            }
        }

        throw new CipheriseException("Attempted to GET " + path + ", but failed to authenticate");
    }

    JSONObject post(String path, JSONObject body) throws CipheriseException {
        for (int i = 0; i < 2; ++i) {
            try {
                return this.webClient.post(path, body, this.sessionId);
            } catch (CipheriseException e) {
                if (e.errorCode == 42) {
                    this.authenticate();
                    continue;
                } else {
                    throw e;
                }
            }
        }

        throw new CipheriseException("Attempted to POST " + path + ", but failed to authenticate");
    }

    private void authenticate() throws CipheriseException {
        final String endpoint = "/sp/authenticate-service";

        JSONObject initiateResponse = this.webClient.get(endpoint + "/" + this.serviceId, null);
        String authToken = initiateResponse.getString("authToken");
        String spAuthChallenge = initiateResponse.getString("spAuthChallenge");
        byte[] spAuthChallengeSolution = this.sign(Hex.decode(spAuthChallenge));

        JSONObject body = new JSONObject();
        body.put("authToken", authToken);
        body.put("spAuthChallengeSolution", CryptoUtil.toHexString(spAuthChallengeSolution));

        this.sessionId = this.webClient.post(endpoint, body, null).getString("sessionId");
    }

    /**
     * Returns the SHA-256 hash, in bytes, of the given string.
     *
     * @param str The string to hash.
     * @return The SHA-256 hash, in bytes, of the string.
     */
    private static byte[] getSHA256HashAsBytes(String str) {
        MessageDigest sha256Digest = null;
        try {
            sha256Digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            sha256Digest.update(str.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        // Send the user enrollment request so that we can get the validation/QR code
        // urls
        return sha256Digest.digest();
    }

    /**
     * Calculates a HMAC signature used for verification of data validity (i.e.
     * detection of data tampering).
     *
     * @param username        The username for which this signature is being used.
     * @param deviceId        The device identifier for which this signature is
     *                        being used.
     * @param publicKeyString The public key represented in PKS#8 format, for which
     *                        this signature is being used.
     * @return A HMAC signature containing the provided data.
     */
    byte[] calculateSignature(String username, String deviceId, String publicKeyString, int level) {
        String signatureContentStr = this.client.getAddress().toLowerCase() + this.getId() + username.toLowerCase()
                + deviceId + publicKeyString + Integer.toString(level);

        return this.sign(getSHA256HashAsBytes(signatureContentStr));
    }

    /**
     * Starts the registration process for a given user.
     *
     * @param username The username to register.
     * @return The ongoing registration session for the user.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Enrolment enrolUser(String username) throws CipheriseException {
        // Create request body
        JSONObject body = new JSONObject();
        body.put("username", username);

        JSONObject res = this.post("/sp/enrol-user", body);
        return new Enrolment(this, res.getString("logId"), username, res.getString("validateURL"),
                res.getString("qrCodeURL"), res.getString("directEnrolURL"), res.getString("statusURL"), null, null,
                null);
    }

    /**
     * Starts an authentication session with the given device.
     *
     * @param authLevel             The authentication level to use.
     * @param username              The username to authenticate.
     * @param device                The device to use for authentication.
     * @param notificationMessage   notificationMessage The message to show to the
     *                              user in the notification.
     * @param authenticationMessage authenticationMessage The message describing the
     *                              authentication, shown to the user in the
     *                              application.
     * @param brandingMessage       The branding associated with this request.
     * @return An authentication session.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Authentication pushAuthenticate(String username, Device device, String notificationMessage,
            String authenticationMessage, String brandingMessage, AuthenticationLevel authLevel)
            throws CipheriseException {
        return startAuthentication("Push", username, device, notificationMessage, authenticationMessage,
                brandingMessage, null, authLevel);
    }

    /**
     * Starts an open consumable authentication session.
     *
     * @param authLevel             The authentication level to use.
     * @param authenticationMessage The message describing the authentication, shown
     *                              to the user in the application.
     * @param brandingMessage       The branding associated with this request.
     * @param appRedirectURL        The URL for the app to redirect to after
     *                              finishing.
     * @return An authentication session
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Authentication waveAuthenticate(String authenticationMessage, String brandingMessage, String appRedirectURL,
            AuthenticationLevel authLevel) throws CipheriseException {
        return startAuthentication("Wave", null, null, null, authenticationMessage, brandingMessage, appRedirectURL,
                authLevel);
    }

    /*
     * The method that does the actual initialisation of the authentication session.
     *
     * @param authMode The mode of authentication used - either 'Push', targeted to
     * an individual, or 'Wave' which allows an individual to consume an
     * authentication via WaveCode.
     *
     * @param username The username of the individual to send authentication to.
     * This is only relevant on 'Push' mode.
     *
     * @param device The device of the individual to send authentication to. This is
     * only relevant on 'Push' mode.
     *
     * @param notificationMessage The message to show to the user in the
     * notification.
     *
     * @param authenticationMessage The message describing the authentication, shown
     * to the user in the application.
     *
     * @param brandingMessage The branding associated with this request.
     *
     * @param appRedirectURL The URL for the app to redirect to after finishing.
     *
     * @param authLevel The authentication level to use.
     */
    private Authentication startAuthentication(String authMode, String username, Device device,
            String notificationMessage, String authenticationMessage, String brandingMessage, String appRedirectURL,
            AuthenticationLevel authLevel) throws CipheriseException {
        // Create the request body
        JSONObject body = new JSONObject();
        body.put("type", "Authentication");
        body.put("interaction", authMode);
        if (authMode.equals("Push")) {
            body.put("username", username);
            body.put("deviceId", device.getId());
        }
        body.put("authenticationMessage", authenticationMessage);
        body.put("notificationMessage", notificationMessage);
        body.put("brandingMessage", brandingMessage);
        if (authMode.equals("Wave") && appRedirectURL != null) {
            body.put("appRedirectURL", appRedirectURL);
        }

        JSONObject res = this.post("/sp/authentication", body);
        Authentication authSession;
        if (authMode.equals("Push")) {
            if (!res.getString("pnErrorMessage").equals("")) {
                throw new CipheriseException("Could not PushAuth: " + res.getString("pnErrorMessage"));
            }

            // Create an auth session to manage this.
            authSession = new Authentication(this, authMode, res.getString("logId"), authLevel,
                    res.getString("appAuthenticationURL"), null, null, res.getString("challengeExchangeURL"),
                    res.getString("statusURL"), username, device, null);
        } else {
            authSession = new Authentication(this, authMode, res.getString("logId"), authLevel,
                    res.getString("appAuthenticationURL"), res.getString("qrURL"), res.getString("directURL"),
                    res.getString("challengeExchangeURL"), res.getString("statusURL"), null, null, null);
        }

        return authSession;
    }

    /**
     * Returns the devices associated with this username, if available.
     *
     * @param username The username to get devices for.
     * @return A list of {@link Device}s attached to this user.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public List<Device> getUserDevices(String username) throws CipheriseException {
        List<Device> devicesList = new ArrayList<>();
        JSONArray devices = this.get("/sp/user-devices/" + username).getJSONArray("devices");

        for (int i = 0; i < devices.length(); i++) {
            JSONObject device = devices.getJSONObject(i);

            String deviceId = device.getString("deviceId");
            String friendlyName = device.getString("friendlyName");

            JSONObject publicKeysJSON = device.getJSONObject("publicKeys");
            JSONObject signatures = device.getJSONObject("signatures");
            Map<Integer, PublicKey> publicKeys = new HashMap<>();
            for (String levelString : publicKeysJSON.keySet()) {
                PublicKey publicKey = CryptoUtil.getPublicKeyFromPKCS8(publicKeysJSON.getString(levelString));
                final Integer level = Integer.valueOf(levelString);
                publicKeys.put(level, publicKey);

                // Reconstruct the signature and validate that it matches with what we have
                byte[] serverSignature = Hex.decode(signatures.getString(levelString));
                byte[] ourSignature = this.calculateSignature(username, deviceId, publicKeysJSON.getString(levelString),
                        level);

                if (!Arrays.equals(serverSignature, ourSignature)) {
                    throw new CipheriseException(
                            "Server returned invalid signature when getting devices for " + username);
                }
            }

            // Add to list once we're sure everything is valid
            devicesList.add(new Device(deviceId, friendlyName, publicKeys));
        }

        return devicesList;
    }

    /**
     * Revokes this service provider.
     *
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public void revoke() throws CipheriseException {
        this.post("/sp/revoke-service", null);
    }

    /**
     * Revokes the given user and all of their devices.
     *
     * @param username The user to revoke.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public void revokeUser(String username) throws CipheriseException {
        JSONObject body = new JSONObject();
        body.put("username", username);

        this.post("/sp/revoke-user", body);
    }

    /**
     * Revokes the given user on the given devices.
     *
     * @param username The user to revoke.
     * @param devices  The devices to revoke.
     * @return The invalid device IDs, if any were provided.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public List<String> revokeUser(String username, List<Device> devices) throws CipheriseException {
        JSONArray devicesJson = new JSONArray();
        for (Device device : devices) {
            devicesJson.put(device.getId());
        }

        JSONObject body = new JSONObject();
        body.put("username", username);
        body.put("deviceIds", devicesJson);

        List<String> invalidDeviceIds = new ArrayList<>();
        JSONArray invalidDeviceIdsJson = this.post("/sp/revoke-user", body).optJSONArray("invalidDeviceIds");
        if (invalidDeviceIdsJson != null) {
            for (int i = 0; i < invalidDeviceIdsJson.length(); i++) {
                invalidDeviceIds.add(invalidDeviceIdsJson.getString(i));
            }
        }

        return invalidDeviceIds;
    }

    /**
     * Serializes this service to a buffer.
     *
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     * @return Serialized data.
     */
    public byte[] serialize() throws CipheriseException {
        try {
            byte[] privateKeyBytes = CryptoUtil.getPKCS1FromPrivateKey(this.privateKey);
            MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
            // @formatter:off
            packer
                .packArrayHeader(6)
                .packString(Service.Header)
                .packString(Client.SERIALIZED_VERSION)
                .packString(this.serviceId)
                .packBinaryHeader(privateKeyBytes.length)
                .writePayload(privateKeyBytes)
                .packNil()
                .packString(this.sessionId);
            // @formatter:on
            packer.close();

            return packer.toByteArray();
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Deserializes a serialized enrolment, so that it can be used after being
     * passed around or stored.
     *
     * @param data The serialized enrolment. Will be validated.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     * @return The enrolment.
     */
    public Enrolment deserializeEnrolment(byte[] data) throws CipheriseException {
        try {
            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data);

            int arrayLength = unpacker.unpackArrayHeader();
            if (arrayLength < 11) {
                throw new CipheriseException("Attempted to deserialize enrolment, but incorrect number of components");
            }

            String header = unpacker.unpackString();
            if (!header.equals(Enrolment.Header)) {
                throw new CipheriseException("Attempted to deserialize enrolment, but header not found");
            }

            String serializedVersion = unpacker.unpackString();
            if (!serializedVersion.equals(Client.SERIALIZED_VERSION)) {
                throw new CipheriseException("Attempted to deserialize authentication, but incorrect version");
            }

            String logId = unpacker.unpackString();
            String WaveCodeUrl = unpacker.unpackString();
            String directEnrolUrl = unpacker.unpackString();
            String statusUrl = unpacker.unpackString();
            String validateUrl = unpacker.unpackString();
            String username = unpacker.unpackString();

            String confirmationUrl = unpacker.tryUnpackNil() ? null : unpacker.unpackString();
            String deviceId = unpacker.tryUnpackNil() ? null : unpacker.unpackString();

            Map<Integer, PublicKey> publicKeys = null;
            if (!unpacker.tryUnpackNil()) {
                publicKeys = new HashMap<>();
                int mapSize = unpacker.unpackMapHeader();

                for (int i = 0; i < mapSize; ++i) {
                    Integer level = Integer.parseInt(unpacker.unpackString());
                    PublicKey publicKey = CryptoUtil.getPublicKeyFromPKCS8(unpacker.unpackString());
                    publicKeys.put(level, publicKey);
                }
            }

            return new Enrolment(this, logId, username, validateUrl, WaveCodeUrl, directEnrolUrl, statusUrl,
                    confirmationUrl, deviceId, publicKeys);
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Deserializes a serialized authentication, so that it can be used after being
     * passed around or stored.
     *
     * @param data The serialized authentication. Will be validated.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     * @return The authentication.
     */
    public Authentication deserializeAuthentication(byte[] data) throws CipheriseException {
        try {
            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data);

            int arrayLength = unpacker.unpackArrayHeader();
            if (arrayLength < 11) {
                throw new CipheriseException(
                        "Attempted to deserialize authentication, but incorrect number of components");
            }

            String header = unpacker.unpackString();
            String serializedVersion = unpacker.unpackString();

            if (!serializedVersion.equals(Client.SERIALIZED_VERSION)) {
                throw new CipheriseException("Attempted to deserialize authentication, but incorrect version");
            }

            if (header.equals(Authentication.PushHeader)) {
                String logId = unpacker.unpackString();

                int challengeLength = unpacker.unpackBinaryHeader();
                ByteBuffer challenge = ByteBuffer.allocate(challengeLength);
                unpacker.readPayload(challenge);

                AuthenticationLevel authLevel = AuthenticationLevel.fromLevel(unpacker.unpackInt());
                String username = unpacker.unpackString();

                int serializedDeviceLength = unpacker.unpackBinaryHeader();
                ByteBuffer serializedDevice = ByteBuffer.allocate(serializedDeviceLength);
                unpacker.readPayload(serializedDevice);
                Device device = Device.deserialize(serializedDevice.array());

                String statusURL = unpacker.unpackString();
                String challengeExchangeURL = unpacker.unpackString();
                String appAuthenticationURL = unpacker.unpackString();
                String verifyAuthenticationURL = unpacker.tryUnpackNil() ? null : unpacker.unpackString();

                return new Authentication(this, "Push", logId, authLevel, appAuthenticationURL, null, null,
                        challengeExchangeURL, statusURL, username, device, verifyAuthenticationURL);
            } else if (header.equals(Authentication.WaveHeader)) {
                String logId = unpacker.unpackString();

                int challengeLength = unpacker.unpackBinaryHeader();
                ByteBuffer challenge = ByteBuffer.allocate(challengeLength);
                unpacker.readPayload(challenge);

                AuthenticationLevel authLevel = AuthenticationLevel.fromLevel(unpacker.unpackInt());
                String directURL = unpacker.unpackString();
                String WaveCodeURL = unpacker.unpackString();
                String statusURL = unpacker.unpackString();
                String appAuthenticationURL = unpacker.unpackString();
                String challengeExchangeURL = unpacker.unpackString();
                String verifyAuthenticationURL = unpacker.tryUnpackNil() ? null : unpacker.unpackString();

                return new Authentication(this, "Wave", logId, authLevel, appAuthenticationURL, WaveCodeURL, directURL,
                        challengeExchangeURL, statusURL, null, null, verifyAuthenticationURL);
            } else {
                throw new CipheriseException("Attempted to deserialize authentication, but header not found");
            }
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        try {
            Service r = (Service) o;
            return this.serviceId.equals(r.serviceId) && this.privateKey.equals(r.privateKey)
                    && this.sessionId.equals(r.sessionId);
        } catch (ClassCastException e) {
            return false;
        }
    }

    JSONObject decryptPayloadJson(PublicKey initiatorPublicKey, JSONObject json) throws CipheriseException {
        byte[] encryptedDataWithIV = Hex.decode(json.getString("data"));
        byte[] encryptedKey = Hex.decode(json.getString("key"));
        byte[] signature = Hex.decode(json.getString("signature"));

        try {
            Signature signatureVerifier = Signature.getInstance("SHA256withRSA");
            signatureVerifier.initVerify(initiatorPublicKey);
            signatureVerifier.update(encryptedKey);
            if (!signatureVerifier.verify(signature)) {
                throw new CipheriseException("Failed payload signature verification");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CipheriseException(e);
        }

        byte[] key = CryptoUtil.rsaDecrypt(this.privateKey, encryptedKey);
        int ivBound = encryptedDataWithIV.length - 16;
        if (ivBound < 0) {
            throw new CipheriseException("Data field insufficiently long for both data and IV");
        }

        byte[] encryptedData = Arrays.copyOfRange(encryptedDataWithIV, 0, ivBound);
        byte[] iv = Arrays.copyOfRange(encryptedDataWithIV, ivBound, encryptedDataWithIV.length);

        byte[] data = CryptoUtil.aes256CfbDecrypt(key, iv, encryptedData);
        return new JSONObject(new String(data, StandardCharsets.UTF_8));
    }

    JSONObject encryptPayloadData(PublicKey recipientPublicKey, JSONObject json) throws CipheriseException {
        String data = json.toString();
        byte[] key = CryptoUtil.generateRandomBytes(256 / 8);
        byte[] iv = CryptoUtil.generateRandomBytes(128 / 8);

        byte[] encryptedData = CryptoUtil.aes256CfbEncrypt(key, iv, data.getBytes());
        byte[] encryptedDataWithIV = Arrays.copyOf(encryptedData, encryptedData.length + iv.length);
        System.arraycopy(iv, 0, encryptedDataWithIV, encryptedData.length, iv.length);

        byte[] encryptedKey = CryptoUtil.rsaEncrypt(recipientPublicKey, key);
        byte[] signature = this.sign(encryptedKey);

        String encryptedDataWithIVHex = CryptoUtil.toHexString(encryptedDataWithIV);
        if (encryptedDataWithIVHex.length() >= this.client.getMaxPayloadSize()) {
            throw new CipheriseException(
                "payload size " +
                Integer.toString(encryptedDataWithIVHex.length()) +
                " exceeds max payload size " +
                Integer.toString(this.client.getMaxPayloadSize())
            );
        }

        JSONObject res = new JSONObject();
        res.put("data", encryptedDataWithIVHex);
        res.put("key", CryptoUtil.toHexString(encryptedKey));
        res.put("signature", CryptoUtil.toHexString(signature));
        return res;
    }
}
