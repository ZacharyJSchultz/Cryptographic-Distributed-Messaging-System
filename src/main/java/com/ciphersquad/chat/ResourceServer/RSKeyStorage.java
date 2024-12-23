package com.ciphersquad.chat.ResourceServer;

public class RSKeyStorage {
  String server;
  byte[] key;

  public RSKeyStorage(String s, byte[] k) {
    server = s;
    key = k;
  }

  public String getServer() {
    return server;
  }
  
  public byte[] getKey() {
    return key;
  }
}
