package com.ciphersquad.chat.client;

import com.ciphersquad.chat.AuthenticationServer.*;

import java.util.HashMap;
import java.util.List;

import javax.crypto.SecretKey;

public class User {
    public String name;
    public String password;
    public Token token;
    public HashMap<Integer, byte[][]> secretKeys;   // Note: SecretKeys are encoded
    public List<byte[]> groupKeys;
    public int reencryptionGroup;
    public boolean needsReencryption;
    public byte[] signature;
    public User() {
        this.name = "";
        this.password = "";
        this.token = new Token();
    }
}