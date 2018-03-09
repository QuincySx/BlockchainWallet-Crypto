package com.quincysx.crypto;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.quincysx.crypto.bip32.ExtendedKey;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bip38.BIP38PrivateKey;
import com.quincysx.crypto.bip38.Bip38;
import com.quincysx.crypto.bip39.SeedCalculator;
import com.quincysx.crypto.bip39.wordlists.English;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;
import com.quincysx.crypto.bip44.CoinPairDerive;
import com.quincysx.crypto.bitcoin.BitCoinECKeyPair;
import com.quincysx.crypto.bitcoin.BitcoinException;
import com.quincysx.crypto.ethereum.CallTransaction;
import com.quincysx.crypto.ethereum.EthECKeyPair;
import com.quincysx.crypto.utils.HexUtils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

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
        List<String> mnemonicWordsInAList = new ArrayList<>();
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

        byte[] seed = new SeedCalculator()
                .withWordsFromWordList(English.INSTANCE)
                .calculateSeed(mnemonicWordsInAList, "");

        try {
//            ExtendedKey extendedKey = ExtendedKey.create(seed);
//            AddressIndex address = BIP44.m().purpose44()
//                    .coinType(1)
//                    .account(0)
//                    .external()
//                    .address(0);
//            CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
//            ExtendedKey master = coinKeyPair.deriveByExtendedKey(address);
//            CoinKeyPair bitcoinKeyPair = coinKeyPair.convertEthKeyPair(new BigInteger(1, master.getMaster().getPrivate()));

            Log.e("=1221=", "==========开始============");

            ExtendedKey extendedKey = ExtendedKey.create(seed);
            AddressIndex address = BIP44.m().purpose44()
                    .coinType(0)
                    .account(0)
                    .external()
                    .address(0);
            CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
            ECKeyPair master = coinKeyPair.derive(address);

            if (master instanceof BitCoinECKeyPair) {
                BitCoinECKeyPair bitCoinECKeyPair = (BitCoinECKeyPair) master;
                Log.e("=1221=", "======================");
                Log.e("=1221private", bitCoinECKeyPair.getWIFPrivateKey());
                Log.e("=1221public=", HexUtils.toHex(bitCoinECKeyPair.getPublic()));
                Log.e("=1221address=", bitCoinECKeyPair.getStrAddress());
                Log.e("=1221=", "======================");

                try {
                    String s = Bip38.encryptNoEcMultiply("123456", bitCoinECKeyPair.getWIFPrivateKey());

                    Log.e("=====", s);

//                    String s1 = Bip38.decrypt(s, "123456");
//
//                    Log.e("=====", s1);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

//                    String s2 = Bip38.bip38DecryptConfirmation(s, "123456");
//                    Log.e("===s===", s2);

            } else if (master instanceof EthECKeyPair) {
                EthECKeyPair ethECKeyPair = (EthECKeyPair) master;
                Log.e("=12221=", "======================");
                Log.e("=12221private", HexUtils.toHex(ethECKeyPair.getPrivate()));
                Log.e("=12221public=", HexUtils.toHex(ethECKeyPair.getPublic()));
                Log.e("=12221address=", HexUtils.toHex(ethECKeyPair.getAddress()));
                Log.e("=12221=", "======================");
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
//            EthTransaction txConst = CallTransaction.createCallTransaction(nonce.longValue(), gasPrice.longValue(), gasLimit.longValue(),
//                    "6b3b3386f46d2872a4bbfda001cebc7dec844593", 0, CallTransaction.Function.fromSignature("balanceOf","address"),"cAfEE4583441D2682bEa06b6E8bFA722a7cea848");
//            txConst.sign((ECKeyPair) master.getMaster());
//            byte[] data = txConst.getData();
//            byte[] rawHash = txConst.getEncoded();
//
//            Log.e("====合约===", HexUtils.toHex(data));
//            Log.e("====签名===", HexUtils.toHex(rawHash));

            //转 Token
//            Transaction txConst = CallTransaction.createCallTransaction(nonce.longValue(), gasPrice.longValue(), gasLimit.longValue(),
//                    "6b3b3386f46d2872a4bbfda001cebc7dec844593", 0,
//                    CallTransaction.Function.fromSignature("transfer",
//                            "address", "uint256"), "4de1f8192dc059cc15f7ba2a045082263cfd1644", 100000000000000000L);
//
//            txConst.sign(master);
//            byte[] data = txConst.getData();
//            byte[] rawHash = txConst.getSignBytes();
//
//            Log.e("====转Token合约参数===", HexUtils.toHex(data));
//            Log.e("====转Token签名===", HexUtils.toHex(rawHash));


        } catch (ValidationException e) {
            e.printStackTrace();
        }

    }
}
