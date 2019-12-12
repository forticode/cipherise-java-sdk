package com.forticode.cipherise;

import org.json.JSONObject;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A client for a Forticode Cipherise server. To use this SDK, instantiate this
 * class and use its methods.
 */
public class Client {
    static final String SERIALIZED_VERSION = "1.0.0"; //todo Check this version and intent

    private final String address;
    private final WebClient webClient;
    private int maxPayloadSize = 0;

    boolean validateServerVersion = true;

    /**
     * Constructs a new Cipherise client.
     *
     * @param address The address of the Cipherise server to connect to.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Client(String address) throws CipheriseException {
        // Trim the URL to remove any extraneous whitespace.
        address = address.trim();

        // Ensure the URL actually exists.
        if (address.isEmpty()) {
            throw new CipheriseException("Expected non-empty URL!");
        }

        // Always add an end-slash.
        address += "/";

        // Remove all duplicate end-slashes until we have just one.
        int endIndex = address.length();
        while (address.charAt(endIndex - 1) == address.charAt(endIndex - 2)) {
            endIndex--;
        }
        address = address.substring(0, endIndex);

        this.address = address;
        this.webClient = new WebClient(address);
    }

    /**
     * @return The Cipherise server address this client will connect to.
     */
    public String getAddress() {
        return this.address;
    }

    /**
     * Retrieves information about the server.
     *
     * @return Information about the server.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public ServerInformation serverInformation() throws CipheriseException {
        JSONObject res = this.webClient.get("/info", null);

        this.maxPayloadSize = res.has("payloadSize") ? res.getInt("payloadSize") : 4000;

        ServerInformation si = new ServerInformation(res.getString("serverVersion"), res.getString("buildVersion"),
                res.getString("appMinVersion"), this.maxPayloadSize);

        // Validate that this version of the CS is supported.
        String[] versionArray = si.serverVersion.split("\\.");
        if (versionArray.length != 3) {
            throw new CipheriseException("Expected three digits for server version, but got " + si.serverVersion);
        }

        int majorVersion = Integer.parseInt(versionArray[0]);
        if (majorVersion < 6) {  //todo This would be best defined elsewhere.....
            throw new CipheriseException(
                    "This version of the Java SDK does not support Cipherise servers older than version 6.x.x. "
                            + "Please either upgrade your Cipherise server or downgrade your SDK, as appropriate.");
        }

        return si;
    }

    /**
     * Creates and registers a Service Provider with the Cipherise Server.
     *
     * @param friendlyName The name of the Service Provider to register.
     * @return The newly-created {@link Service}.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Service createService(String friendlyName) throws CipheriseException {
        // If validating server version, call `serverInformation` to force retrieval
        // of the version.
        if (this.validateServerVersion) {
            this.serverInformation();
        }

        // Generate a keypair
        KeyPair keyPair = CryptoUtil.generateRSAKeyPair(2048);

        // Get the public and private key as bytes
        PublicKey publicKey = keyPair.getPublic();

        // Create a request body
        JSONObject body = new JSONObject();
        body.put("friendlyName", friendlyName);
        body.put("publicKey", CryptoUtil.getPKCS8FromPublicKey(publicKey));

        // Send a request to the Cipherise Server
        JSONObject response = this.webClient.post("/sp/create-service", body, null);
        String serviceId = response.getString("serviceId");

        return new Service(this, this.webClient, serviceId, keyPair.getPrivate());
    }

    /**
     * Deserializes the buffer into a {@link Service}.
     *
     * @param data The buffer to deserialize.
     * @return The newly-created {@link Service}.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public Service deserializeService(byte[] data) throws CipheriseException {
        // If validating server version, call `serverInformation` to force retrieval
        // of the version.
        if (this.validateServerVersion) {
            this.serverInformation();
        }

        try {
            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data);

            int arrayLength = unpacker.unpackArrayHeader();
            if (arrayLength < 5) {
                throw new CipheriseException("Attempted to deserialize service, but incorrect number of components");
            }

            String header = unpacker.unpackString();
            if (!header.equals(Service.Header)) {
                throw new CipheriseException("Attempted to deserialize service, but header not found");
            }

            if (arrayLength == 5) {
                String serviceId = unpacker.unpackString();

                int privateKeyLength = unpacker.unpackBinaryHeader();
                byte[] privateKeyBytes = unpacker.readPayload(privateKeyLength);
                PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPKCS1(privateKeyBytes);

                // Ignore the signature key (deprecated).
                unpacker.unpackValue();

                String sessionId = unpacker.tryUnpackNil() ? "" : unpacker.unpackString();
                return new Service(this, this.webClient, serviceId, privateKey, sessionId);
            } else if (arrayLength == 6) {
                String serializedVersion = unpacker.unpackString();
                if (!serializedVersion.equals(Client.SERIALIZED_VERSION)) {
                    throw new CipheriseException("Attempted to deserialize service, but incorrect version");
                }

                String serviceId = unpacker.unpackString();

                int privateKeyLength = unpacker.unpackBinaryHeader();
                byte[] privateKeyBytes = unpacker.readPayload(privateKeyLength);
                PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPKCS1(privateKeyBytes);

                // Ignore the signature key (deprecated).
                unpacker.unpackValue();

                String sessionId = unpacker.tryUnpackNil() ? "" : unpacker.unpackString();
                return new Service(this, this.webClient, serviceId, privateKey, sessionId);
            } else {
                throw new CipheriseException("Attempted to deserialize service, but incorrect number of components");
            }
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Retrieves the maximum supported payload size.
     * @return The maximum payload size in bytes.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public int getMaxPayloadSize() throws CipheriseException {
        if (this.maxPayloadSize == 0) {
            this.serverInformation();
        }

        return this.maxPayloadSize;
    }
}
