package com.quincysx.crypto.bip38;

import com.quincysx.crypto.ECKeyPair;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bitcoin.BitCoinECKeyPair;

import java.math.BigInteger;

/**
 * @author QuincySx
 * @date 2018/3/8 下午2:39
 */
public class Bip38ECKeyPair extends BitCoinECKeyPair {
    public static final int TYPE_BIP38 = 4;


    public final String confirmationCode;
    public final String wifPrivateKey;

    public Bip38ECKeyPair(String priv, String wifPrivateKey, String confirmationCode, boolean compressed) throws ValidationException {
        super(new BigInteger("0"), compressed);
        this.confirmationCode = confirmationCode;
        this.wifPrivateKey = wifPrivateKey;
    }

    public String getConfirmationCode() {
        return confirmationCode;
    }

    @Override
    public String getWIFPrivateKey() {
        return wifPrivateKey;
    }
}
