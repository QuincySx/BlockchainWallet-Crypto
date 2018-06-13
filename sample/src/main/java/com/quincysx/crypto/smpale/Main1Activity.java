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
import com.quincysx.crypto.bip39.MnemonicGenerator;
import com.quincysx.crypto.bip39.RandomSeed;
import com.quincysx.crypto.bip39.SeedCalculator;
import com.quincysx.crypto.bip39.WordCount;
import com.quincysx.crypto.bip39.wordlists.English;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;
import com.quincysx.crypto.bip44.CoinPairDerive;
import com.quincysx.crypto.bitcoin.BTCTransaction;
import com.quincysx.crypto.bitcoin.BitcoinException;
import com.quincysx.crypto.eos.EOSECKeyPair;
import com.quincysx.crypto.ethereum.EthECKeyPair;
import com.quincysx.crypto.ethereum.keystore.CipherException;
import com.quincysx.crypto.ethereum.keystore.KeyStore;
import com.quincysx.crypto.ethereum.keystore.KeyStoreFile;
import com.quincysx.crypto.utils.HexUtils;

import org.spongycastle.jcajce.provider.digest.SHA256;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class Main1Activity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        List<String> strings = new ArrayList<>();
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");
        strings.add("a");

        byte[] seed = new SeedCalculator().calculateSeed(strings, "");
        byte[] seed = new byte[0];
        try {
            seed = com.quincysx.crypto.utils.SHA256.sha256("a a a a a a a a a a a a".getBytes("Utf-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }


//        byte[] seed = new SeedCalculator().calculateSeed(strings, "");
        EOSECKeyPair eosecKeyPair = new EOSECKeyPair(new BigInteger(seed));

//        EOSECKeyPair eosecKeyPair = new EOSECKeyPair(ECKeyPair.createNew(true));

//        try {
//            EOSECKeyPair eosecKeyPair = EOSECKeyPair.parse("5JLwgEmaMivG4h4TH6T9WXMCerVU9SqTrrVm5g89idvG9CT4GUg");
        //public  EOS6iGwqWSuGK9JGNxbU1kM4DoadTAHNNcuAvJ1EyU5BUJy9u3dQa

        Log.e("=private=", eosecKeyPair.getPrivateKey());
        Log.e("=public=", eosecKeyPair.getPublicKey());
//        } catch (ValidationException e) {
//            e.printStackTrace();
//        }

    }
}
