package com.quincysx.crypto.bip44;

import com.quincysx.crypto.bip32.Index;

/**
 * @author QuincySx
 * @date 2018/3/5 下午4:28
 */
public class AddressIndex {
    private final Change change;
    private final int addressIndex;

    private final String string;

    AddressIndex(final Change change, final int addressIndex) {
        this.change = change;
        this.addressIndex = addressIndex;
        string = String.format("%s/%d", change, addressIndex);
    }

    public int getValue() {
        return addressIndex;
    }

    public Change getParent() {
        return change;
    }

    @Override
    public String toString() {
        return string;
    }
}
