package com.quincysx.crypto.bitcoin;

import com.quincysx.crypto.TrulySecureRandom;
import com.quincysx.crypto.utils.Base58Check;
import com.quincysx.crypto.utils.HexUtils;

import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.crypto.signers.HMacDSAKCalculator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * @author QuincySx
 * @date 2018/3/2 下午3:12
 */
public class SignTransaction {
    public static final TrulySecureRandom SECURE_RANDOM = new TrulySecureRandom();
    private static X9ECParameters params = SECNamedCurves.getByName("secp256k1");
    private static ECDomainParameters EC_PARAMS = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());

    /**
     * 签名方法 支持交易单签 and 同地址多Input多签
     *
     * @param transaction 交易
     * @return 签名完的交易
     */
    public static BTCTransaction signTransaction(BTCTransaction transaction, BigInteger privateKeyBigInteger, byte[] publicKey, String address) {
        BTCTransaction.Input[] signedInput = new BTCTransaction.Input[transaction.inputs.length];
        for (int i = 0; i < transaction.inputs.length; i++) {
            signedInput[i] = sign(transaction, i, privateKeyBigInteger, publicKey, address, BTCTransaction.Script.SIGHASH_ALL);
        }
        return new BTCTransaction(signedInput, transaction.outputs, transaction.lockTime);
    }

    /**
     * 对单个Input进行签名
     *
     * @param transaction 交易
     * @param index       Input索引
     * @reture 签名完毕的Input
     */
    public static BTCTransaction.Input sign(BTCTransaction transaction, int index, BigInteger privateKeyBigInteger, byte[] publicKey, String address, byte ScriptType) {
        String publicScript = mkPubKeyScript(address);
        //清空无关Input的Script,对相关Script进行签名
        signatureForm(transaction, index, publicScript);

        //双 Sha256 and 签名
        byte[] signature = sign(privateKeyBigInteger, BTCTransaction.Script.hashTransactionForSigning(transaction));

        //拼版本
        byte[] signatureAndHashType = new byte[signature.length + 1];
        System.arraycopy(signature, 0, signatureAndHashType, 0, signature.length);
        signatureAndHashType[signatureAndHashType.length - 1] = ScriptType;

        //拼出新的input
        return new BTCTransaction.Input(transaction.inputs[index].outPoint, new BTCTransaction.Script(signatureAndHashType, publicKey), transaction.inputs[index].sequence);
    }

    /**
     * 设置Input的地址签名
     *
     * @param transaction  交易
     * @param index        索引
     * @param publicScript 地址签名
     * @return 新的交易
     */
    private static BTCTransaction signatureForm(BTCTransaction transaction, int index, String publicScript) {
        //存放清空地址签名的Input
        for (int i = 0; i < transaction.inputs.length; i++) {
            BTCTransaction.Script script = null;
            if (i == index) {
                //设置地址签名
                script = new BTCTransaction.Script(HexUtils.fromHex(publicScript));
            }
            transaction.inputs[i] = new BTCTransaction.Input(transaction.inputs[i].outPoint, script, transaction.inputs[i].sequence);
        }
        return transaction;
    }

    /**
     * 签署地址签名
     *
     * @param address 地址
     * @return 签名
     */
    private static String mkPubKeyScript(String address) {
        //设置加密格式
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("76a914");

        //设置签名
        byte[] bytes = Base58Check.base58ToBytes(address);
        byte[] checkByte = new byte[bytes.length - 1];
        System.arraycopy(bytes, 1, checkByte, 0, checkByte.length);
        stringBuilder.append(HexUtils.toHex(checkByte));

        Arrays.fill(bytes, (byte) 0);
        Arrays.fill(checkByte, (byte) 0);

        //设置签名后缀格式
        stringBuilder.append("88ac");
        return stringBuilder.toString();
    }

    public static byte[] sign(BigInteger privateKey, byte[] input) {
        synchronized (EC_PARAMS) {
//            ECDSASigner signer = new ECDSASigner();
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            ECPrivateKeyParameters privateKeyParam = new ECPrivateKeyParameters(privateKey, EC_PARAMS);
            signer.init(true, new ParametersWithRandom(privateKeyParam, SECURE_RANDOM));
            BigInteger[] sign = signer.generateSignature(input);
            BigInteger r = sign[0];
            BigInteger s = sign[1];
            BigInteger largestAllowedS = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);//SECP256K1_N_DIV_2
            if (s.compareTo(largestAllowedS) > 0) {
                //https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#low-s-values-in-signatures
                s = BitCoinKeyPairGenerator.LARGEST_PRIVATE_KEY.subtract(s);
            }
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream(72);
                DERSequenceGenerator derGen = new DERSequenceGenerator(baos);
                derGen.addObject(new ASN1Integer(r));
                derGen.addObject(new ASN1Integer(s));
                derGen.close();
                return baos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

}
