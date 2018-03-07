package com.quincysx.crypto;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.quincysx.crypto.bip32.ExtendedKey;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bip39.SeedCalculator;
import com.quincysx.crypto.bip39.wordlists.English;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;
import com.quincysx.crypto.bip44.CoinPairDerive;
import com.quincysx.crypto.ethereum.EthTransaction;
import com.quincysx.crypto.utils.Base64;
import com.quincysx.crypto.utils.HexUtils;

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
        List<String> mnemonicWordsInAList = new ArrayList<>();
        mnemonicWordsInAList.add("flavor");
        mnemonicWordsInAList.add("casual");
        mnemonicWordsInAList.add("library");
        mnemonicWordsInAList.add("knee");
        mnemonicWordsInAList.add("shy");
        mnemonicWordsInAList.add("erupt");
        mnemonicWordsInAList.add("wall");
        mnemonicWordsInAList.add("until");
        mnemonicWordsInAList.add("usual");
        mnemonicWordsInAList.add("bronze");
        mnemonicWordsInAList.add("scout");
        mnemonicWordsInAList.add("immune");

        byte[] seed = new SeedCalculator()
                .withWordsFromWordList(English.INSTANCE)
                .calculateSeed(mnemonicWordsInAList, "");

        try {
            ExtendedKey extendedKey = ExtendedKey.create(seed);
            AddressIndex address = BIP44.m().purpose44()
                    .coinType(1)
                    .account(0)
                    .external()
                    .address(0);
            CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
            ExtendedKey master = coinKeyPair.deriveByExtendedKey(address);

            CoinKeyPair bitcoinKeyPair = coinKeyPair.convertEthKeyPair(new BigInteger(1, master.getMaster().getPrivate()));

            Log.e("=1231=", "======================");
            Log.e("=1231=", bitcoinKeyPair.getPrivateKey());
            Log.e("=1231=", bitcoinKeyPair.getPublicKey());
            Log.e("=1231=", bitcoinKeyPair.getAddress());
            Log.e("=1231=", "======================");

            BigInteger nonce = new BigInteger("0");
            BigInteger gasPrice = new BigInteger("8000000000");
            BigInteger gasLimit = new BigInteger("21000");

            EthTransaction ethTransaction = EthTransaction
                    .create("cAfEE4583441D2682bEa06b6E8bFA722a7cea848",
                            new BigInteger("10000000000000000"),
                            nonce,
                            gasPrice,
                            gasLimit, 3);
            ethTransaction.sign((ECKeyPair) master.getMaster());

            byte[] rawHash = ethTransaction.getEncoded();

            Log.e("====签名===", HexUtils.toHex(rawHash));
        } catch (ValidationException e) {
            e.printStackTrace();
        }

    }
}
