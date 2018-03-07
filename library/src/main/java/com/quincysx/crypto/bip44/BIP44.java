package com.quincysx.crypto.bip44;

import android.support.annotation.IntDef;

/**
 * @author QuincySx
 * @date 2018/3/5 下午3:36
 */
public final class BIP44 {

    private static final M M = new M();

    BIP44() {
    }

    /**
     * Start creating a BIP44 path.
     *
     * @return A fluent factory for creating BIP44 paths
     */
    public static M m() {
        return M;
    }
}
