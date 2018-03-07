/*
 * Copyright 2013 bits of proof zrt.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.quincysx.crypto;

import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.utils.Base58;
import com.quincysx.crypto.utils.RIPEMD160;
import com.quincysx.crypto.utils.SHA256;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;


public class ECKeyPair implements Key {
    protected static final SecureRandom secureRandom = new SecureRandom();
    protected static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");
    protected static final ECDomainParameters domain = new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());

    protected BigInteger priv;
    protected byte[] pub;
    protected byte[] pubComp;
    protected boolean compressed;

    protected ECKeyPair() {
    }

    public ECKeyPair(byte[] p, boolean compressed) throws ValidationException {
        this(new BigInteger(1, p), compressed);
        if (p.length != 32) {
            throw new ValidationException("Invalid private key");
        }
    }

    public ECKeyPair(BigInteger priv, boolean compressed) {
        this.priv = priv;
        this.compressed = compressed;

        ECPoint multiply = CURVE.getG().multiply(priv);
        this.pub = multiply.getEncoded(false);
        this.pubComp = multiply.getEncoded(true);
    }

    protected ECKeyPair(Key keyPair) {
        this.priv = new BigInteger(1, keyPair.getPrivate());
        this.compressed = keyPair.isCompressed();
        this.pub = keyPair.getPublic();
        this.pubComp = keyPair.getCompPublic();
    }

    @Override
    public boolean isCompressed() {
        return compressed;
    }

    @Override
    public ECKeyPair clone() throws CloneNotSupportedException {
        ECKeyPair c = (ECKeyPair) super.clone();
        c.priv = new BigInteger(c.priv.toByteArray());
        c.pub = Arrays.clone(pub);
        c.pubComp = Arrays.clone(pubComp);
        c.compressed = compressed;
        return c;
    }

    public static ECKeyPair createNew(boolean compressed) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(domain, secureRandom);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        ECKeyPair k = new ECKeyPair();
        k.priv = privParams.getD();
        k.compressed = compressed;
        ECPoint multiply = CURVE.getG().multiply(k.priv);
        k.pub = multiply.getEncoded(false);
        k.pubComp = multiply.getEncoded(true);
        return k;
    }

    public void setPublic(byte[] pub) throws ValidationException {
        throw new ValidationException("Can not set public key if private is present");
    }

    @Override
    public byte[] getPrivate() {
        byte[] p = priv.toByteArray();

        if (p.length != 32) {
            byte[] tmp = new byte[32];
            System.arraycopy(p, Math.max(0, p.length - 32), tmp, Math.max(0, 32 - p.length), Math.min(32, p.length));
            p = tmp;
        }
        return p;
    }

    @Override
    public byte[] getPublic() {
        return Arrays.clone(pub);
    }

    @Override
    public byte[] getCompPublic() {
        return Arrays.clone(pubComp);
    }

    @Override
    public byte[] getAddress() {
        return RIPEMD160.hash160(pubComp);
    }

    public byte[] signBTC(byte[] hash) throws ValidationException {
        if (priv == null) {
            throw new ValidationException("Need private key to sign");
        }
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new ECPrivateKeyParameters(priv, domain));
        BigInteger[] signature = signer.generateSignature(hash);
        ByteArrayOutputStream s = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator seq = new DERSequenceGenerator(s);
            seq.addObject(new DERInteger(signature[0]));
            seq.addObject(new DERInteger(signature[1]));
            seq.close();
            return s.toByteArray();
        } catch (IOException e) {
        }
        return null;
    }

    public boolean verifyBTC(byte[] hash, byte[] signature) {
        return verify(hash, signature, pubComp);
    }

    @Override
    public <T> T sign(byte[] messageHash) {
        throw new RuntimeException("Please convert to ECKeyPair subclass signature");
    }

    public static boolean verify(byte[] hash, byte[] signature, byte[] pub) {
        ASN1InputStream asn1 = new ASN1InputStream(signature);
        try {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(CURVE.getCurve().decodePoint(pub), domain));

            DLSequence seq = (DLSequence) asn1.readObject();
            BigInteger r = ((DERInteger) seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((DERInteger) seq.getObjectAt(1)).getPositiveValue();
            return signer.verifySignature(hash, r, s);
        } catch (Exception e) {
            // threat format errors as invalid signatures
            return false;
        } finally {
            try {
                asn1.close();
            } catch (IOException e) {
            }
        }
    }

    public static String serializeWIF(Key key) {
        return Base58.encode(bytesWIF(key));
    }

    private static byte[] bytesWIF(Key key) {
        byte[] k = key.getPrivate();
        if (key.isCompressed()) {
            byte[] encoded = new byte[k.length + 6];
            byte[] ek = new byte[k.length + 2];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            ek[k.length + 1] = 0x01;
            byte[] hash = SHA256.doubleSha256(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        } else {
            byte[] encoded = new byte[k.length + 5];
            byte[] ek = new byte[k.length + 1];
            ek[0] = (byte) 0x80;
            System.arraycopy(k, 0, ek, 1, k.length);
            byte[] hash = SHA256.doubleSha256(ek);
            System.arraycopy(ek, 0, encoded, 0, ek.length);
            System.arraycopy(hash, 0, encoded, ek.length, 4);
            return encoded;
        }
    }

    public static ECKeyPair parseWIF(String serialized) throws ValidationException {
        byte[] store = Base58.decode(serialized);
        return parseBytesWIF(store);
    }

    public static ECKeyPair parseBytesWIF(byte[] store) throws ValidationException {
        if (store.length == 37) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 5];
            System.arraycopy(store, 1, key, 0, store.length - 5);
            return new ECKeyPair(key, false);
        } else if (store.length == 38) {
            checkChecksum(store);
            byte[] key = new byte[store.length - 6];
            System.arraycopy(store, 1, key, 0, store.length - 6);
            return new ECKeyPair(key, true);
        }
        throw new ValidationException("Invalid key length");
    }

    private static void checkChecksum(byte[] store) throws ValidationException {
        byte[] checksum = new byte[4];
        System.arraycopy(store, store.length - 4, checksum, 0, 4);
        byte[] ekey = new byte[store.length - 4];
        System.arraycopy(store, 0, ekey, 0, store.length - 4);
        byte[] hash = SHA256.doubleSha256(ekey);
        for (int i = 0; i < 4; ++i) {
            if (hash[i] != checksum[i]) {
                throw new ValidationException("checksum mismatch");
            }
        }
    }
}
