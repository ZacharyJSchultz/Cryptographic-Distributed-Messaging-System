package com.ciphersquad.chat.AuthenticationServer;

import java.io.Serializable;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.Mac;
import java.util.Arrays;



public class AuthIntegrityMessage implements Serializable {
    private byte[] ciphertext;
    private byte[] hmacDigest;

    public AuthIntegrityMessage(byte[] ciphertext, byte[] hmacDigest) {
        this.ciphertext = ciphertext;
        this.hmacDigest = hmacDigest;
    }

    public AuthIntegrityMessage(byte[] ciphertext, Mac hmac) {
        this.ciphertext = ciphertext;
        hmac.update(ciphertext, 0, ciphertext.length);
        byte[] hmacResult = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacResult, 0);
        this.hmacDigest = hmacResult;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }

    public byte[] getHmacDigest() {
        return hmacDigest;
    }

    public boolean verifyHmac(Mac hmac) {
        // Run the HMAC algorithm with the given key and the ciphertext
        hmac.update(ciphertext, 0, ciphertext.length);
        byte[] hmacResult = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacResult, 0);
        
        // Compare the result with the stored HMAC
        return Arrays.equals(hmacResult, hmacDigest);
    }


}