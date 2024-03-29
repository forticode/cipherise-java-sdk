package com.forticode.cipherise;

import java.io.IOException;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

/**
 * Device with the Cipherise authentication app installed on it.
 */
public class Device {
    final static String Header = "CiphDvce";

    private String id;
    private String name;
    private Map<Integer, PublicKey> publicKeys;

    /**
     * Constructs a Device. Not to be used directly; use
     * {@link Service#getUserDevices(String)} to retrieve devices.
     *
     * @param id         The identifier of the device, as provided by the Cipherise
     *                   Server.
     * @param name       The friendly name of the device, as provided by the user.
     * @param publicKeys The public keys of the device, as generated by the
     *                   Cipherise app on the device.
     */
    Device(String id, String name, Map<Integer, PublicKey> publicKeys) {
        this.id = id;
        this.name = name;
        this.publicKeys = publicKeys;
    }

    /**
     * @return The identifier associated with this device.
     */
    public String getId() {
        return this.id;
    }

    /**
     * @return The friendly name associated with this device.
     */
    public String getName() {
        return this.name;
    }

    /**
     * @return The public keys associated with this device.
     */
    public Map<Integer, PublicKey> getPublicKeys() {
        return this.publicKeys;
    }

    @Override
    public boolean equals(Object o) {
        try {
            Device r = (Device) o;

            return
                this.id.equals(r.id) &&
                this.name.equals(r.name) &&
                this.publicKeys.equals(r.publicKeys);
        } catch (ClassCastException e) {
            return false;
        }
    }

    /**
     * Serializes this device to a buffer that can be stored elsewhere.
     *
     * @return The serialized device as bytes.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    public byte[] serialize() throws CipheriseException {
        try {
            MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
            // @formatter:off
            packer
                .packArrayHeader(5)
                .packString(Device.Header)
                .packString(Client.SERIALIZED_VERSION)
                .packString(this.id)
                .packString(this.name);

            packer.packMapHeader(this.publicKeys.size());
            for (Map.Entry<Integer, PublicKey> entry : publicKeys.entrySet()) {
                packer.packString(entry.getKey().toString());
                packer.packString(CryptoUtil.getPKCS8FromPublicKey(entry.getValue()));
            }
            // @formatter:on
            packer.close();

            return packer.toByteArray();
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Deserializes a serialized device, so that it can be used after being passed
     * around or stored.
     *
     * @param data The serialized device.
     * @return The deserialized Device.
     * @throws CipheriseException Any exceptions thrown by Cipherise.
     */
    static public Device deserialize(byte[] data) throws CipheriseException {
        try {
            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data);

            int arrayLength = unpacker.unpackArrayHeader();
            if (arrayLength != 5) {
                throw new CipheriseException("Attempted to deserialize device, but incorrect number of components");
            }

            String header = unpacker.unpackString();
            if (!header.equals(Device.Header)) {
                throw new CipheriseException("Attempted to deserialize device, but header not found");
            }

            String serializedVersion = unpacker.unpackString();
            if (!serializedVersion.equals(Client.SERIALIZED_VERSION)) {
                throw new CipheriseException("Attempted to deserialize version, but incorrect version");
            }

            String id = unpacker.unpackString();
            String name = unpacker.unpackString();

            Map<Integer, PublicKey> publicKeys = new HashMap<>();
            int mapSize = unpacker.unpackMapHeader();

            for (int i = 0; i < mapSize; ++i) {
                Integer level = Integer.parseInt(unpacker.unpackString());
                PublicKey publicKey = CryptoUtil.getPublicKeyFromPKCS8(unpacker.unpackString());
                publicKeys.put(level, publicKey);
            }

            return new Device(id, name, publicKeys);
        } catch (IOException e) {
            throw new CipheriseException(e);
        }
    }
}
