package com.quincysx.crypto;

import com.quincysx.crypto.ethereum.ETHKeyPair;

/**
 * @author QuincySx
 * @date 2018/3/2 上午10:55
 */
public class CoinKeyPair {
    private final String privateKey;
    private final String publicKey;
    private final String address;

    public CoinKeyPair(String privateKey, String publicKey, String address) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.address = address;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return String.format("[Private key: %s, Public key: %s]", privateKey, publicKey);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || this.getClass() != object.getClass()) return false;
        CoinKeyPair that = (CoinKeyPair) object;
        return privateKey.equals(that.privateKey) && publicKey.equals(that.publicKey);
    }

    @Override
    public int hashCode() {
        int result = privateKey.hashCode();
        result = 31 * result + publicKey.hashCode();
        return result;
    }
}
