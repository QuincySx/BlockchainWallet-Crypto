package com.quincysx.crypto.bip44;

import com.quincysx.crypto.CoinKeyPair;
import com.quincysx.crypto.bip32.ExtendedKey;
import com.quincysx.crypto.bip32.Index;
import com.quincysx.crypto.bip32.ValidationException;
import com.quincysx.crypto.bitcoin.BitCoinKeyPairGenerator;
import com.quincysx.crypto.ethereum.ETHKeyPairGenerator;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * @author QuincySx
 * @date 2018/3/5 下午3:48
 */
public class CoinPairDerive {
    private static Map<String, ExtendedKey> sExtendedKeyMap = new WeakHashMap<>();

    private ExtendedKey mExtendedKey;

    public CoinPairDerive(ExtendedKey extendedKey) {
        mExtendedKey = extendedKey;
    }

    public ExtendedKey deriveByExtendedKey(AddressIndex addressIndex) throws ValidationException {
        ExtendedKey extendedKey = sExtendedKeyMap.get(addressIndex.toString());
        if (extendedKey != null) {
            return extendedKey;
        }
        int address = addressIndex.getValue();
        int change = addressIndex.getParent().getValue();
        int account = addressIndex.getParent().getParent().getValue();
        int coinType = addressIndex.getParent().getParent().getParent().getValue();
        int purpose = addressIndex.getParent().getParent().getParent().getParent().getValue();

        ExtendedKey child = mExtendedKey
                .getChild(Index.hard(purpose))
                .getChild(Index.hard(coinType))
                .getChild(Index.hard(account))
                .getChild(change)
                .getChild(address);
        sExtendedKeyMap.put(addressIndex.toString(), child);
        return child;
    }

    public CoinKeyPair derive(AddressIndex addressIndex) throws ValidationException {
        int coinType = addressIndex.getParent().getParent().getParent().getValue();
        ExtendedKey child = deriveByExtendedKey(addressIndex);
        CoinKeyPair coinKeyPair = convertKeyPair(child, coinType);
        return coinKeyPair;
    }

    public CoinKeyPair convertKeyPair(ExtendedKey child, int coinType) throws ValidationException {
        switch (coinType) {
            case 1:
                return convertBitcoinKeyPair(new BigInteger(1, child.getMaster().getPrivate()), true);
            case 60:
                return convertEthKeyPair(new BigInteger(1, child.getMaster().getPrivate()));
            case 0:
            default:
                return convertBitcoinKeyPair(new BigInteger(1, child.getMaster().getPrivate()), false);
        }
    }

    public CoinKeyPair convertBitcoinKeyPair(BigInteger integer, boolean testNet) throws ValidationException {
        try {
            BitCoinKeyPairGenerator generator = new BitCoinKeyPairGenerator();
            return generator.generateBitcoinKeyPair(integer, testNet, true);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        }
    }

    public CoinKeyPair convertEthKeyPair(BigInteger integer) throws ValidationException {
        try {
            ETHKeyPairGenerator generator = new ETHKeyPairGenerator();
            return generator.generateETHKeyPair(integer);
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            throw new ValidationException(e);
        }
    }
}
