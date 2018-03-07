package com.quincysx.crypto;

import com.quincysx.crypto.bip39.MnemonicGenerator;
import com.quincysx.crypto.bip39.SeedCalculator;
import com.quincysx.crypto.bip39.Words;
import com.quincysx.crypto.bip39.wordlists.English;
import com.quincysx.crypto.bip44.Account;
import com.quincysx.crypto.bip44.AddressIndex;
import com.quincysx.crypto.bip44.BIP44;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

/**
 * @author QuincySx
 * @date 2018/3/2 下午5:29
 */
public class Bip32UnitTest {
    @Test
    public void addition_isCorrect() throws Exception {
        assertEquals(4, 2 + 2);
        final StringBuilder sb = new StringBuilder();

        byte[] entropy = new byte[Words.TWELVE.byteLength()];
        new SecureRandom().nextBytes(entropy);
        new MnemonicGenerator(English.INSTANCE)
                .createMnemonic(entropy, new MnemonicGenerator.Target() {
                    @Override
                    public void append(CharSequence string) {
                        sb.append(string);
                    }
                });

        byte[] seed = new SeedCalculator().calculateSeed(sb.toString(), "");


    }
}
