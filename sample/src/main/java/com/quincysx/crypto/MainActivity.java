package com.quincysx.crypto;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.quincysx.crypto.bip32.ExtendedKey;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bip38.Bip38;
import com.quincysx.crypto.bip39.MnemonicCode;
import com.quincysx.crypto.bip39.MnemonicException;
import com.quincysx.crypto.bip39.RandomSeed;
import com.quincysx.crypto.bip39.Words;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;
import com.quincysx.crypto.bip44.CoinPairDerive;
import com.quincysx.crypto.bitcoin.BitCoinECKeyPair;
import com.quincysx.crypto.exception.CoinNotFindException;
import com.quincysx.crypto.exception.NonSupportException;
import com.quincysx.crypto.utils.HexUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

//import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.*;
import org.web3j.crypto.WalletFile;

import static org.web3j.crypto.Wallet.createStandard;

import com.missionpublic.blockchain.Account;

public class MainActivity extends AppCompatActivity {

    private static final int N = 1 << 9;
    /**
     * Parallelization parameter. Must be a positive integer less than or equal to Integer.MAX_VALUE / (128 * r * 8).
     */
    private static final int P = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        try {
//            long time1 = System.currentTimeMillis();
//            BitCoinKeyPairGenerator generator = new BitCoinKeyPairGenerator();
//            long time2 = System.currentTimeMillis();
//            BitcoinKeyPair bitcoinKeyPair = generator.generateBitcoinKeyPair(true, false);
//            long time3 = System.currentTimeMillis();
//            Log.e("===private===", bitcoinKeyPair.getPrivateKey());
//            Log.e("===public===", bitcoinKeyPair.getPublicKey());
//            Log.e("===address===", bitcoinKeyPair.getAddress());
//
//            Log.e("===时间1===", String.format("%d", time2 - time1));
//            Log.e("===时间2===", String.format("%d", time3 - time2));
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }

//        try {
//            long time1 = System.currentTimeMillis();
//            ETHKeyPairGenerator generator = new ETHKeyPairGenerator();
//            long time2 = System.currentTimeMillis();
//            ETHKeyPair ethKeyPair = generator.generateETHKeyPair();
//            long time3 = System.currentTimeMillis();
//            Log.e("===private===", ethKeyPair.getPrivateKey());
//            Log.e("===public===", ethKeyPair.getPublicKey());
//            Log.e("===address===", ethKeyPair.getAddress());
//
//            Log.e("===时间1===", String.format("%d", time2 - time1));
//            Log.e("===时间2===", String.format("%d", time3 - time2));
//        } catch (InvalidAlgorithmParameterException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
        final List<String> mnemonicWordsInAList = new ArrayList<>();
//        mnemonicWordsInAList.add("flavor");
//        mnemonicWordsInAList.add("casual");
//        mnemonicWordsInAList.add("library");
//        mnemonicWordsInAList.add("knee");
//        mnemonicWordsInAList.add("shy");
//        mnemonicWordsInAList.add("erupt");
//        mnemonicWordsInAList.add("wall");
//        mnemonicWordsInAList.add("until");
//        mnemonicWordsInAList.add("usual");
//        mnemonicWordsInAList.add("bronze");
//        mnemonicWordsInAList.add("scout");
//        mnemonicWordsInAList.add("immune");

        mnemonicWordsInAList.add("age");
        mnemonicWordsInAList.add("jazz");
        mnemonicWordsInAList.add("plunge");
        mnemonicWordsInAList.add("quantum");
        mnemonicWordsInAList.add("envelope");
        mnemonicWordsInAList.add("crime");
        mnemonicWordsInAList.add("dial");
        mnemonicWordsInAList.add("foster");
        mnemonicWordsInAList.add("lunch");
        mnemonicWordsInAList.add("amazing");
        mnemonicWordsInAList.add("athlete");
        mnemonicWordsInAList.add("diet");
        try {
            Account account = new Account("123456");
            Log.e("1111111", account.getAddress());
            Log.e("2222222", account.getKeyStore());
            Log.e("=====", "===" + account.getMnemonic());


            Account account1 = new Account("{\"address\":\"128a5f2969df5dac41863f6fd227435c6c5b5665\",\"id\":\"fa4960b2-62c1-4e70-b4ae-505b5f2141d2\",\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"cipherparams\":{\"iv\":\"ad357c89d5b96ed7c97b73ba8c0840de\"},\"ciphertext\":\"25cbfe0726ca818ecdbff485d9a80f6b359d38ded758b8c6d52089d813b1b6ee\",\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":262144,\"p\":1,\"r\":8,\"salt\":\"6aece844bcc5eef5ee9505328b83422e25aa87e5cb612e07dabe05e78d902814\"},\"mac\":\"53abf903bef4bce498cbef75e61254dc2a64cb7a5a377075fff5ca954d42b6f5\"}}","123456");
            Log.e("333333", account1.getAddress());
            Log.e("444444", account1.getKeyStore());

            Account account2 = new Account(mnemonicWordsInAList,"123456");
            Log.e("555555", account2.getPrivateKey());
            Log.e("666666", account2.getKeyStore());

            Account account3 = new Account(HexUtils.fromHex("08bb06bba09340dc6934d4ed3b613b801f76b9838c53406a5753854fe622bc90"),"123456");
            Log.e("777777", account3.getPrivateKey());
            Log.e("888888", account3.getKeyStore());

            byte[] random = RandomSeed.random(Words.TWELVE);
            MnemonicCode mnemonicCode = new MnemonicCode();
            List<String> strings = mnemonicCode.toMnemonic(random);
            byte[] bytes = mnemonicCode.toEntropy(strings);

            byte[] seed = MnemonicCode.toSeed(mnemonicWordsInAList, "");

//            ExtendedKey extendedKey = ExtendedKey.create(seed);
//            AddressIndex address = BIP44.m().purpose44()
//                    .coinType(1)
//                    .account(0)
//                    .external()
//                    .address(0);
//            CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
//            ExtendedKey master = coinKeyPair.deriveByExtendedKey(address);
//            CoinKeyPair bitcoinKeyPair = coinKeyPair.convertEthKeyPair(new BigInteger(1, master
// .getMaster().getPrivate()));

            Log.e("=1221=", "==========开始============");

            ExtendedKey extendedKey = ExtendedKey.create(seed);
            AddressIndex address = BIP44.m().purpose44()
                    .coinType(CoinTypes.Ethereum)
                    .account(0)
                    .external()
                    .address(0);
            CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
            ECKeyPair master = coinKeyPair.derive(address);

            org.web3j.crypto.ECKeyPair keypair = org.web3j.crypto.ECKeyPair.create(master.getRawPrivateKey());

            WalletFile walletFile = createStandard("111111", keypair);

            Log.e("=1221=", "==" + address.toString());
            Log.e("=1221private", master.getPrivateKey());
            Log.e("=1221public=", master.getPublicKey());
            Log.e("=1221address=", master.getAddress());
            Log.e("=1221=", "======================");

            if (master instanceof BitCoinECKeyPair) {
                try {
                    String s = Bip38.encryptNoEcMultiply("123456", master
                            .getPrivateKey());
                    Log.e("=====", s);
                    BitCoinECKeyPair s1 = Bip38.decrypt(s, "123456");

                    Log.e("=====", s1.getPrivateKey());
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            //普通上链签名=========
            BigInteger nonce = new BigInteger("12");
            BigInteger gasLimit = new BigInteger("1500000");
//            BigInteger gasLimit = new BigInteger("21000");
            BigInteger gasPrice = new BigInteger("5000000000");
//            BigInteger gasPrice = new BigInteger("0");
//
//            EthTransaction ethTransaction = EthTransaction
//                    .create("cAfEE4583441D2682bEa06b6E8bFA722a7cea848",
//                            new BigInteger("10000000000000000"),
//                            nonce,
//                            gasPrice,
//                            gasLimit, 3);
//            ethTransaction.sign((ECKeyPair) master.getMaster());
//
//            byte[] rawHash = ethTransaction.getEncoded();
//
//            Log.e("====签名===", HexUtils.toHex(rawHash));


//            //调用合约查余额====
//            EthTransaction txConst = CallTransaction.createCallTransaction(nonce.longValue(),
// gasPrice.longValue(), gasLimit.longValue(),
//                    "6b3b3386f46d2872a4bbfda001cebc7dec844593", 0, CallTransaction.Function
// .fromSignature("balanceOf","address"),"cAfEE4583441D2682bEa06b6E8bFA722a7cea848");
//            txConst.sign((ECKeyPair) master.getMaster());
//            byte[] data = txConst.getData();
//            byte[] rawHash = txConst.getEncoded();
//
//            Log.e("====合约===", HexUtils.toHex(data));
//            Log.e("====签名===", HexUtils.toHex(rawHash));

            //转 Token
//            Transaction txConst = CallTransaction.createCallTransaction(nonce.longValue(),
// gasPrice.longValue(), gasLimit.longValue(),
//                    "6b3b3386f46d2872a4bbfda001cebc7dec844593", 0,
//                    CallTransaction.Function.fromSignature("transfer",
//                            "address", "uint256"), "4de1f8192dc059cc15f7ba2a045082263cfd1644",
// 100000000000000000L);
//
//            txConst.sign(master);
//            byte[] data = txConst.getData();
//            byte[] rawHash = txConst.getSignBytes();
//
//            Log.e("====转Token合约参数===", HexUtils.toHex(data));
//            Log.e("====转Token签名===", HexUtils.toHex(rawHash));


        } catch (ValidationException e) {
            e.printStackTrace();
        } catch (MnemonicException.MnemonicLengthException e) {
            e.printStackTrace();
        } catch (MnemonicException.MnemonicChecksumException e) {
            e.printStackTrace();
        } catch (MnemonicException.MnemonicWordException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        String s = BIP44.m()
                .purpose44()
                .coinType(CoinTypes.Ethereum)
                .account(0)
                .external()
                .address(1, true).toString();
        Log.e("=====", "address1  " + s);
        try {
            AddressIndex addressIndex = BIP44.parsePath(s);
            String s1 = addressIndex.toString();
            Log.e("=====", "address2  " + s1);
        } catch (NonSupportException e) {
            e.printStackTrace();
        } catch (CoinNotFindException e) {
            e.printStackTrace();
        }
    }
}
