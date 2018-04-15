package com.quincysx.crypto.smpale;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.quincysx.crypto.CoinTypes;
import com.quincysx.crypto.ECKeyPair;
import com.quincysx.crypto.bip32.ExtendedKey;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bip39.MnemonicCode;
import com.quincysx.crypto.bip39.MnemonicException;
import com.quincysx.crypto.bip39.RandomSeed;
import com.quincysx.crypto.bip39.Words;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;
import com.quincysx.crypto.bip44.CoinPairDerive;
import com.quincysx.crypto.ethereum.EthECKeyPair;
import com.quincysx.crypto.ethereum.keystore.CipherException;
import com.quincysx.crypto.ethereum.keystore.KeyStore;
import com.quincysx.crypto.ethereum.keystore.KeyStoreFile;

import java.io.IOException;
import java.math.BigInteger;
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

        Log.e("=====", "===" + mnemonicWordsInAList.toString());
        try {
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

            Log.e("=1221=", "==" + address.toString());
            Log.e("=1221private", master.getPrivateKey());
            Log.e("=1221public=", master.getPublicKey());
            Log.e("=1221address=", master.getAddress());
            Log.e("=1221=", "======================");

            if (master instanceof EthECKeyPair) {
                try {
                    KeyStoreFile light = KeyStore.createLight("123456", (EthECKeyPair) master);

                    Log.e("======", light.toString());
                } catch (CipherException e) {
                    e.printStackTrace();
                }
            }

            KeyStoreFile keyStoreFile = KeyStoreFile.parse("{\"address\":\"cafee4583441d2682bea06b6e8bfa722a7cea848\"," +
                            "\"id\":\"1562c4fe-c714-4187-ad62-6baff33e3633\",\"version\":3," +
                            "\"crypto\":{\"cipher\":\"aes-128-ctr\"," +
                            "\"cipherparams\":{\"iv\":\"e0ba8a361141cc01f6860170ab8ee25c\"}," +
                            "\"ciphertext\":\"4ee617421d4283c706c2bd48f43739d58b4aede740b62208f78cd33427419062\",\"kdf\":\"scrypt\",\"kdfparams\":{\"dklen\":32,\"n\":4096,\"p\":6,\"r\":8,\"salt\":\"85aab20aa7398f4dc0cde887c3b44c5d0ac2a5419dd6eb026272cccc55dc2588\"},\"mac\":\"29dd9c95c69611926cc826df68d65899fe11f18990d3dac7ba3778980e5a45ec\"}}");

            try {
                ECKeyPair decrypt = KeyStore.decrypt("123456", keyStoreFile);

                Log.e("=12321=", "==" + decrypt.toString());
                Log.e("=12321private", decrypt.getPrivateKey());
                Log.e("=12321public=", decrypt.getPublicKey());
                Log.e("=12321address=", decrypt.getAddress());
                Log.e("=12321=", "======================");
            } catch (CipherException e) {
                e.printStackTrace();
            }

//            try {
//                BTCTransaction btcTransaction = new BTCTransaction(HexUtils.fromHex
//
// ("02000000018aad5febb0f5165097727eb402d15e96c615560b6d4e0fcbee0882ff589af3220000000000ffffffff0240420f00000000001976a91438ae48c4ff53e9ba952d3c63f200f2dfe04f330188aca0cd8700000000001976a91481f9f80df4efb08e373fa8f2b8896f33e3a270f388ac00000000"));
//                byte[] sign = btcTransaction.sign(master);
//                Log.e("===", HexUtils.toHex(sign));
//            } catch (BitcoinException e) {
//                e.printStackTrace();
//            }

//            Log.e("=====", "================================================sdasdasdasd");
//            BitCoinECKeyPair bitCoinECKeyPair = BitCoinECKeyPair.parseWIF(master.getPrivateKey());
//            Log.e("=====", "================================================sdasdasdasd");
//
//            Log.e("=1221private", bitCoinECKeyPair.getPrivateKey());
//            Log.e("=1221public=", bitCoinECKeyPair.getPublicKey());
//            Log.e("=1221address=", bitCoinECKeyPair.getAddress());
//            Log.e("=1221=", "======================");

//            if (master instanceof BitCoinECKeyPair) {
//                try {
//                    String s = Bip38.encryptNoEcMultiply("123456", master
//                            .getPrivateKey());
//                    Log.e("=====", s);
//                    BitCoinECKeyPair s1 = Bip38.decrypt(s, "123456");
//
//                    Log.e("=====", s1.getPrivateKey());
//                } catch (InterruptedException e) {
//                    e.printStackTrace();
//                }
//            }

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


            //调用合约查余额====
//            CallTransaction.Function function = CallTransaction.Function
//                    .fromSignature("balanceOf", "address");
//            byte[] data = function.encode("cAfEE4583441D2682bEa06b6E8bFA722a7cea848");
//
//            Log.e("====合约===", HexUtils.toHex(data));


            //转 Token
//            Transaction txConst = CallTransaction.createCallTransaction(nonce,
//                    gasPrice, gasLimit,
//                    "6b3b3386f46d2872a4bbfda001cebc7dec844593", new BigInteger("0"),
//                    CallTransaction.Function.fromSignature("transfer",
//                            "address", "uint256"), "4de1f8192dc059cc15f7ba2a045082263cfd1644",
//                    new BigInteger("100000000000000000"));
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
        } catch (JsonParseException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

//        String s = BIP44.m()
//                .purpose44()
//                .coinType(CoinTypes.Ethereum)
//                .account(0)
//                .external()
//                .address(1, true).toString();
//        Log.e("=====", "address1  " + s);
//        try {
//            AddressIndex addressIndex = BIP44.parsePath(s);
//            String s1 = addressIndex.toString();
//            Log.e("=====", "address2  " + s1);
//        } catch (NonSupportException e) {
//            e.printStackTrace();
//        } catch (CoinNotFindException e) {
//            e.printStackTrace();
//        }

    }
}
