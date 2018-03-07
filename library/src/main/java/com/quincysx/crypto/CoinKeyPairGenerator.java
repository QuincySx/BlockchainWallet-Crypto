package com.quincysx.crypto;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECPrivateKeySpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author QuincySx
 * @date 2018/3/1 下午5:36
 */
public class CoinKeyPairGenerator {
    private static final String EC_GEN_PARAM_SPEC = "secp256k1";
    private static final String KEY_PAIR_GEN_ALGORITHM = "ECDSA";

    public static final BigInteger LARGEST_PRIVATE_KEY = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);//SECP256K1_N

    private static final Provider PROVIDER = new BouncyCastleProvider();
    private static final ECNamedCurveParameterSpec EC_NAMED_CURVE_PARAMETER_SPEC = ECNamedCurveTable.getParameterSpec(EC_GEN_PARAM_SPEC);
    private final SecureRandom mSecureRandom;
    private final KeyFactory keyFactory;
    private final KeyPairGenerator mKeyPairGenerator;

    public CoinKeyPairGenerator() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        this(new TrulySecureRandom());
    }

    public CoinKeyPairGenerator(SecureRandom secureRandom) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        mSecureRandom = secureRandom;
        mKeyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER);
        mKeyPairGenerator.initialize(EC_NAMED_CURVE_PARAMETER_SPEC, secureRandom); //TODO: external seed
        keyFactory = KeyFactory.getInstance(KEY_PAIR_GEN_ALGORITHM, PROVIDER);
    }

    /**
     * Generates a random ECDSA key pair
     *
     * @return ECDSA (secp256k1) key pair
     */
    public KeyPair generateEcdsaKeyPair() {
        KeyPair keyPair;
        BigInteger privateKeyBigInteger;
        do {
            keyPair = mKeyPairGenerator.generateKeyPair();
            privateKeyBigInteger = ((ECPrivateKey) keyPair.getPrivate()).getS();
        }
        while (privateKeyBigInteger.compareTo(BigInteger.ONE) < 0 || privateKeyBigInteger.compareTo(LARGEST_PRIVATE_KEY) > 0);
        return keyPair;
    }

    /**
     * Generates a ECDSA (secp256k1) keypair from a secret exponent
     *
     * @param secretExponent
     * @return ECDSA key pair
     * @throws InvalidKeySpecException
     */
    public KeyPair generateEcdsaKeyPair(BigInteger secretExponent) throws InvalidKeySpecException {
        KeySpec privateKeySpec = new ECPrivateKeySpec(secretExponent, EC_NAMED_CURVE_PARAMETER_SPEC);
        ECPoint ecPoint = EC_NAMED_CURVE_PARAMETER_SPEC.getG().multiply(secretExponent);
        KeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, EC_NAMED_CURVE_PARAMETER_SPEC);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }
}
