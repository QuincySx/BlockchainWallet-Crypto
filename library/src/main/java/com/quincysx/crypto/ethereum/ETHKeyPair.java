package com.quincysx.crypto.ethereum;

import com.quincysx.crypto.CoinKeyPair;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DLSequence;
import org.spongycastle.asn1.ocsp.Signature;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.SignatureException;

/**
 * @author QuincySx
 * @date 2018/3/1 下午8:40
 */
public class ETHKeyPair extends CoinKeyPair {

    public ETHKeyPair(String privateKey, String publicKey, String address) {
        super(privateKey, publicKey, address);
    }

    @Override
    public String getPrivateKey() {
        return "0x" + super.getPrivateKey();
    }

    @Override
    public String getPublicKey() {
        return "0x" + super.getPublicKey();
    }

    @Override
    public String getAddress() {
        return "0x" + super.getAddress();
    }
}
