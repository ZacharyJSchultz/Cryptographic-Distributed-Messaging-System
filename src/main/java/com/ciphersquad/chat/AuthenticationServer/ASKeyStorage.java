package com.ciphersquad.chat.AuthenticationServer;

public class ASKeyStorage {
  int id;
  int version;
  byte[] key;

  public ASKeyStorage(int i, int ver, byte[] k) {
    id = i;
    version = ver;
    key = k;
  }

  public int getGroupID() {
    return id;
  }

  public int getVersion() {
    return version;
  }
  
  public byte[] getKey() {
    return key;
  }
}
