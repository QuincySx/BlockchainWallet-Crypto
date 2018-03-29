/**
 * Created by huliqun on 2018/3/21.
 */
package com.missionpublic.blockchain;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
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
import com.quincysx.crypto.utils.RIPEMD160;
import com.quincysx.crypto.utils.HexUtils;

import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;

import org.web3j.crypto.*;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.crypto.WalletFile;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.TransactionEncoder;


import static org.web3j.crypto.Wallet.createLight;
import static org.web3j.crypto.Wallet.decrypt;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class Account {
    protected org.web3j.crypto.ECKeyPair keypair;
    protected WalletFile walletFile;
    protected List<String> mnemonicWordsInAList;

    public Account() {
    }

    public Account(String password) throws MnemonicException.MnemonicLengthException, ValidationException, CipherException {
        byte[] random = RandomSeed.random(Words.TWELVE);
        MnemonicCode mnemonicCode = new MnemonicCode();

        this.mnemonicWordsInAList = mnemonicCode.toMnemonic(random);

        byte[] seed = MnemonicCode.toSeed(this.mnemonicWordsInAList, "");

        ExtendedKey extendedKey = ExtendedKey.create(seed);
        AddressIndex address = BIP44.m().purpose44()
                .coinType(CoinTypes.Ethereum)
                .account(0)
                .external()
                .address(0);
        CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
        ECKeyPair master = coinKeyPair.derive(address);
        this.keypair = org.web3j.crypto.ECKeyPair.create(master.getRawPrivateKey());
        this.walletFile = createLight(password, this.keypair);
    }

    public Account(List<String> mnemonicWordsInAList, String password) throws ValidationException, CipherException {
        this.mnemonicWordsInAList = mnemonicWordsInAList;
        byte[] seed = MnemonicCode.toSeed(mnemonicWordsInAList, "");

        ExtendedKey extendedKey = null;

        extendedKey = ExtendedKey.create(seed);

        AddressIndex address = BIP44.m().purpose44()
                .coinType(CoinTypes.Ethereum)
                .account(0)
                .external()
                .address(0);
        CoinPairDerive coinKeyPair = new CoinPairDerive(extendedKey);
        ECKeyPair master = coinKeyPair.derive(address);
        this.keypair = org.web3j.crypto.ECKeyPair.create(master.getRawPrivateKey());
        this.walletFile = createLight(password, this.keypair);
    }

    public Account(byte[] privateKey, String password) {
        try {
            this.keypair = org.web3j.crypto.ECKeyPair.create(privateKey);
            this.walletFile = createLight(password, this.keypair);
        } catch (CipherException e) {
            e.printStackTrace();
        }
    }

    public Account(String keystore, String password) throws IOException, CipherException {
        ObjectMapper mapper = new ObjectMapper();
        this.walletFile = mapper.readValue(keystore, WalletFile.class);
        this.keypair = decrypt(password, this.walletFile);
    }

    public byte[] getRawPrivateKey() {
        return this.keypair.getPrivateKey().toByteArray();
    }

    public byte[] getRawPublicKey() {
        return this.keypair.getPublicKey().toByteArray();
    }

    public String getPrivateKey() {
        return HexUtils.toHex(this.keypair.getPrivateKey().toByteArray());
    }

    public String getPublicKey() {
        return HexUtils.toHex(this.keypair.getPublicKey().toByteArray());
    }

    public String getAddress() {
        return this.walletFile.getAddress();
    }

    public String getMnemonic() {
        return this.mnemonicWordsInAList.toString();
    }

    public String getKeyStore() throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        String jsonStr = mapper.writeValueAsString(this.walletFile);
        return jsonStr;
    }

    public String changePassword(String password) throws JsonProcessingException, CipherException {
        ObjectMapper mapper = new ObjectMapper();
        this.walletFile = createLight(password, this.keypair);
        String jsonStr = mapper.writeValueAsString(this.walletFile);
        return jsonStr;
    }

    public void setWallet(String keystore) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        this.walletFile = mapper.readValue(keystore, WalletFile.class);
    }

    public void decryptWallet(String password) throws CipherException {
        this.keypair = decrypt(password, this.walletFile);
    }

    public String createSignTransaction(BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, String to,
                                        BigInteger value, String data) throws CipherException {
        RawTransaction tran = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, data);
        Credentials cred = Credentials.create(this.keypair);
        byte[] signResult = TransactionEncoder.signMessage(tran, cred);
        return HexUtils.toHex(signResult);
    }
}
