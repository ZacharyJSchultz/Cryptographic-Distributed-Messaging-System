package com.ciphersquad.chat.ResourceServer;

import com.google.gson.Gson;

public class RSMessages implements java.io.Serializable {

  private byte[] groupMessage; // JSON String of the GroupMessage Object, Deserialise to decrypt
  private byte[] IV;
  private byte[] HMAC;
  private String sender;

  public RSMessages(byte[] _message, byte[] _IV, String _sender, byte[] _HMAC) {
    groupMessage = _message;
    IV = _IV;
    sender = _sender;
    HMAC = _HMAC;
  }

  public String getSender() {
    return sender;
  }

  public byte[] getIV() {
    return IV;
  }

  public byte[] getMessage() {
    return groupMessage;
  }

  public byte[] getHMAC() {
    return HMAC;
  }

  public static String serializeMessage(RSMessages msg) {
    Gson serialiser = new Gson();
    return serialiser.toJson(msg);
  }

  public static RSMessages deserializeMessage(String obj) {
    Gson serialiser = new Gson();
    return serialiser.fromJson(obj, RSMessages.class);
  }
}