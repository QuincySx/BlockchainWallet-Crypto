package com.quincysx.crypto.bitcoin;

import com.quincysx.crypto.CoinKeyPair;

/**
 * @author QuincySx
 * @date 2018/3/1 下午8:40
 */
public class BitcoinKeyPair extends CoinKeyPair {
    private final boolean testNet;
    private final boolean Compressed;

    public BitcoinKeyPair(String privateKey, boolean testNet, boolean compressed, String publicKey, String address) {
        super(privateKey, publicKey, address);
        this.testNet = testNet;
        Compressed = compressed;
    }

    public boolean isTestNet() {
        return testNet;
    }

    public boolean isCompressed() {
        return Compressed;
    }
}
