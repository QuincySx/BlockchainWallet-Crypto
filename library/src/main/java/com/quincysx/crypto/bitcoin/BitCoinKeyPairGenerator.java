package com.quincysx.crypto.bitcoin;

import com.quincysx.crypto.CoinKeyPairGenerator;
import com.quincysx.crypto.utils.Base58;
import com.quincysx.crypto.utils.Base64;
import com.quincysx.crypto.utils.HexUtils;
import com.quincysx.crypto.utils.RIPEMD160;
import com.quincysx.crypto.utils.SHA256;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author QuincySx
 * @date 2018/3/1 下午6:04
 */
public class BitCoinKeyPairGenerator extends CoinKeyPairGenerator {
    private static final int MAIN_NET_PRIVATE_KEY_PREFIX = 0x80;
    private static final int TEST_NET_PRIVATE_KEY_PREFIX = 0xef;
    private static final int MAIN_NET_PRIVATE_KEY_SUFFIX = 0x01;

    private static final int TEST_NET_ADDRESS_SUFFIX = 0x6f;
    private static final int MAIN_NET_ADDRESS_SUFFIX = 0x00;

    private static final int RAW_PRIVATE_KEY_COMPRESSED_LENGTH = 38;
    private static final int RAW_PRIVATE_KEY_NO_COMPRESSED_LENGTH = 37;

    private static final String PUBLIC_KEY_COMPRESSED_EVEN_PREFIX = "02";
    private static final String PUBLIC_KEY_COMPRESSED_ODD_PREFIX = "03";
    private static final String PUBLIC_KEY_NO_COMPRESSED_PREFIX = "04";

    public BitCoinKeyPairGenerator() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    }

    public BitCoinKeyPairGenerator(SecureRandom secureRandom) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        super(secureRandom);
    }

    public BitcoinKeyPair generateBitcoinKeyPair(boolean testNet, boolean isPublicKeyCompressed) {
        KeyPair keyPair = generateEcdsaKeyPair();
        return generateBitcoinKeyPair(keyPair, testNet, isPublicKeyCompressed);
    }

    public BitcoinKeyPair generateBitcoinKeyPair(BigInteger privKeyBigInteger, boolean testNet, boolean isPublicKeyCompressed) throws InvalidKeySpecException {
        if (privKeyBigInteger.compareTo(BigInteger.ONE) < 0 || privKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) > 0) {
            throw new RuntimeException("私钥大小不合法");
        }
        KeyPair keyPair = generateEcdsaKeyPair(privKeyBigInteger);
        return generateBitcoinKeyPair(keyPair, testNet, isPublicKeyCompressed);
    }

    public BitcoinKeyPair generateBitcoinKeyPair(KeyPair keyPair, boolean testNet, boolean isPublicKeyCompressed) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();

        //生成出普通 raw 私钥
        String rawBitcoinPrivateKey = Base64.encode(ecPrivateKey.getS());

        //针对 区块链生成 WIF 格式私钥
        String bitcoinPrivateKey = generateBitcoinPrivateKeyWif(rawBitcoinPrivateKey, testNet, isPublicKeyCompressed);

        String bitcoinPublicKey = generateBitcoinPublicKey(ecPublicKey, isPublicKeyCompressed);

        String address = publicKeyToAddress(testNet, bitcoinPublicKey);

        return new BitcoinKeyPair(bitcoinPrivateKey, testNet, isPublicKeyCompressed, bitcoinPublicKey, address);
    }

    private String generateBitcoinPrivateKeyWif(String rawBitcoinPrivateKey, boolean testNet, boolean isPublicKeyCompressed) {
        byte[] bytes = HexUtils.fromHex(rawBitcoinPrivateKey);
        byte[] rawPrivateKey = new byte[isPublicKeyCompressed ? RAW_PRIVATE_KEY_COMPRESSED_LENGTH : RAW_PRIVATE_KEY_NO_COMPRESSED_LENGTH];
        System.arraycopy(bytes, 0, rawPrivateKey, 1, bytes.length);

        rawPrivateKey[0] = (byte) (testNet ? TEST_NET_PRIVATE_KEY_PREFIX : MAIN_NET_PRIVATE_KEY_PREFIX);
        if (isPublicKeyCompressed) {
            rawPrivateKey[rawPrivateKey.length - 5] = MAIN_NET_PRIVATE_KEY_SUFFIX;
        }

        byte[] check = SHA256.doubleSha256(rawPrivateKey, 0, rawPrivateKey.length - 4);
        System.arraycopy(check, 0, rawPrivateKey, rawPrivateKey.length - 4, 4);

        return Base58.encode(rawPrivateKey);
    }

    public static boolean verifyChecksum(byte[] bytesWithChecksumm) {
        if (bytesWithChecksumm == null || bytesWithChecksumm.length < 5) {
            return false;
        }
        byte[] calculatedDigest = SHA256.doubleSha256(bytesWithChecksumm, 0, bytesWithChecksumm.length - 4);
        boolean checksumValid = true;
        for (int i = 0; i < 4; i++) {
            if (calculatedDigest[i] != bytesWithChecksumm[bytesWithChecksumm.length - 4 + i]) {
                checksumValid = false;
            }
        }
        return checksumValid;
    }

    public BitcoinKeyPair decodePrivateKey(String encodedPrivateKey) {
        if (encodedPrivateKey.length() > 0) {
            try {
                byte[] decoded = Base58.decode(encodedPrivateKey);
                if (decoded != null
                        && (decoded.length == RAW_PRIVATE_KEY_COMPRESSED_LENGTH || decoded.length == RAW_PRIVATE_KEY_NO_COMPRESSED_LENGTH)
                        && ((decoded[0] & 0xff) == MAIN_NET_PRIVATE_KEY_PREFIX || (decoded[0] & 0xff) == TEST_NET_PRIVATE_KEY_PREFIX)) {
                    if (verifyChecksum(decoded)) {
                        boolean testNet = (decoded[0] & 0xff) == TEST_NET_PRIVATE_KEY_PREFIX;
                        byte[] secret = new byte[32];
                        System.arraycopy(decoded, 1, secret, 0, secret.length);
                        boolean isPublicKeyCompressed;
                        if (decoded.length == RAW_PRIVATE_KEY_COMPRESSED_LENGTH) {
                            if (decoded[decoded.length - 5] == 1) {
                                isPublicKeyCompressed = true;
                            } else {
                                return null;
                            }
                        } else {
                            isPublicKeyCompressed = false;
                        }
                        BigInteger privateKeyBigInteger = new BigInteger(1, secret);
                        if (privateKeyBigInteger.compareTo(BigInteger.ONE) > 0 && privateKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) < 0) {
                            return generateBitcoinKeyPair(privateKeyBigInteger, testNet, isPublicKeyCompressed);
                        }
                    }
                } else if (decoded != null && decoded.length == 43 && (decoded[0] & 0xff) == 0x01 && ((decoded[1] & 0xff) == 0x43 || (decoded[1] & 0xff) == 0x42)) {
                    if (verifyChecksum(decoded)) {
//                        return new PrivateKeyInfo(false, Bip38PrivateKeyInfo.TYPE_BIP38, encodedPrivateKey, null, false);
                    }
                }
            } catch (Exception ignored) {
            }
        }
        // TODO: 2018/3/1 需要处理Bip38加密
        return null;
    }

    private String generateBitcoinPublicKey(ECPublicKey ecPublicKey, boolean isPublicKeyCompressed) {
        StringBuilder PubKeyBuilder = new StringBuilder();
        ECPoint q = ecPublicKey.getW();
        BigInteger affineX = q.getAffineX();
        BigInteger affineY = q.getAffineY();
        if (isPublicKeyCompressed) {
            //生成压缩 公钥
            BigInteger remainder = affineY.remainder(new BigInteger("2"));

            if (remainder.intValue() == 0) {
                PubKeyBuilder.append(PUBLIC_KEY_COMPRESSED_EVEN_PREFIX);
            } else {
                PubKeyBuilder.append(PUBLIC_KEY_COMPRESSED_ODD_PREFIX);
            }
            PubKeyBuilder.append(Base64.encode(affineX));
        } else {
            //生成未压缩 公钥
            PubKeyBuilder.append(PUBLIC_KEY_NO_COMPRESSED_PREFIX);
            PubKeyBuilder.append(Base64.encode(affineX));
            PubKeyBuilder.append(Base64.encode(affineY));
        }
        return PubKeyBuilder.toString();
    }

    public static String publicKeyToAddress(boolean testNet, String publicKey) {
        //进行 Sha256 Ripemd160 运算
        byte[] hashedPublicKey = RIPEMD160.hash160(HexUtils.fromHex(publicKey));
        byte[] addressBytes = new byte[1 + hashedPublicKey.length + 4];
        //拼接测试网络或正式网络前缀
        addressBytes[0] = (byte) (testNet ? TEST_NET_ADDRESS_SUFFIX : MAIN_NET_ADDRESS_SUFFIX);

        System.arraycopy(hashedPublicKey, 0, addressBytes, 1, hashedPublicKey.length);
        //进行双 Sha256 运算
        byte[] check = SHA256.doubleSha256(addressBytes, 0, addressBytes.length - 4);

        //将双 Sha256 运算的结果前 4位 拼接到尾部
        System.arraycopy(check, 0, addressBytes, hashedPublicKey.length + 1, 4);

        Arrays.fill(hashedPublicKey, (byte) 0);
        Arrays.fill(check, (byte) 0);
        return Base58.encode(addressBytes);
    }
}
