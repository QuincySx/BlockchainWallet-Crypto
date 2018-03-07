package com.quincysx.crypto.ethereum;

import android.util.Log;

import com.quincysx.crypto.CoinKeyPairGenerator;
import com.quincysx.crypto.bitcoin.BitcoinKeyPair;
import com.quincysx.crypto.utils.Base64;
import com.quincysx.crypto.utils.HexUtils;
import com.quincysx.crypto.utils.KECCAK256;

import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;

/**
 * @author QuincySx
 * @date 2018/3/2 上午10:54
 */
public class ETHKeyPairGenerator extends CoinKeyPairGenerator {
    public ETHKeyPairGenerator() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    }

    public ETHKeyPairGenerator(SecureRandom secureRandom) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        super(secureRandom);
    }

    public ETHKeyPair generateETHKeyPair() {
        KeyPair keyPair = generateEcdsaKeyPair();
        return generateETHKeyPair(keyPair);
    }

    public ETHKeyPair generateETHKeyPair(BigInteger privKeyBigInteger) throws InvalidKeySpecException {
        if (privKeyBigInteger.compareTo(BigInteger.ONE) < 0 || privKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) > 0) {
            throw new RuntimeException("私钥大小不合法");
        }
        KeyPair keyPair = generateEcdsaKeyPair(privKeyBigInteger);
        return generateETHKeyPair(keyPair);
    }

    private ETHKeyPair generateETHKeyPair(KeyPair keyPair) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

        String privateKey = Base64.encode(ecPrivateKey.getS());

        String publicKey = generateETHPublicKey(ecPublicKey);

        String address = publicKeyToAddress(publicKey);
        return new ETHKeyPair(privateKey, publicKey, address);
    }

    private String generateETHPublicKey(ECPublicKey ecPublicKey) {
        StringBuilder PubKeyBuilder = new StringBuilder();

        ECPoint q = ecPublicKey.getW();
        BigInteger affineX = q.getAffineX();
        BigInteger affineY = q.getAffineY();
        PubKeyBuilder.append(Base64.encode(affineX));
        PubKeyBuilder.append(Base64.encode(affineY));

        return PubKeyBuilder.toString();
    }

    private String publicKeyToAddress(String bitcoinPublicKey) {
        byte[] byteAddress = KECCAK256.keccak256(HexUtils.fromHex(bitcoinPublicKey));
        byte[] address = new byte[20];
        System.arraycopy(byteAddress, 12, address, 0, address.length);
        return  HexUtils.toHex(address);
    }
}
