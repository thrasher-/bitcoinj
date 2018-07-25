package org.bitcoinj.core;

public class ScryptHash extends Sha256Hash {

    public ScryptHash(byte[] rawHashBytes) {
        super(rawHashBytes);
    }

    public ScryptHash(String hexString) {
        super(hexString);
    }

    public static ScryptHash wrap(byte[] rawHashBytes) {
        return new ScryptHash(rawHashBytes);
    }

    public static ScryptHash wrapReversed(byte[] rawHashBytes) {
        return wrap(Utils.reverseBytes(rawHashBytes));
    }
    
}