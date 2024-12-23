package com.ciphersquad.chat.ResourceServer;

import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;

public class GroupMessage implements java.io.Serializable {

  private byte[] theMessage;  // Made this (and RSMessages GroupMessage) private. Do they need to be public? If so, just change them back and delete this comment
  private byte[] IV;
  private byte[] HMAC;
  private String sender;
  private int counter;
  private int keyVersion;
  private boolean endToEndEncrypted;

  public GroupMessage(byte[] _message, byte[] _IV, byte[] _HMAC, String _sender, int _keyVersion, int _counter,
      boolean _endToEndEncrypted) {
    theMessage = _message;
    IV = _IV;
    sender = _sender;
    HMAC = _HMAC;
    keyVersion = _keyVersion;
    counter = _counter;
    endToEndEncrypted = _endToEndEncrypted;
  }

  public String getSender() {
    return sender;
  }

  public int getKeyVersion() {
    return keyVersion;
  }

  public int getCounter() {
    return counter;
  }

  public void setCounter(int _counter) {
    counter = _counter;
  }

  public byte[] getHMAC() {
    return HMAC;
  }

  public byte[] getIV() {
    return IV;
  }

  public byte[] getMessage() {
    return theMessage;
  }

  // For cases where a message is decrypted on client, and we want to return the same GroupMessage object while changing the message to the decrypted version
  public void setMessage(byte[] msg) {
    theMessage = msg;
  }

  public String getMessageStr() {
    if (endToEndEncrypted)
      return "";
    return new String(theMessage, StandardCharsets.UTF_8);
  }

  public boolean getEndToEndEncrypted() {
    return endToEndEncrypted;
  }

  public static String serializeMessage(GroupMessage msg) {
    Gson serialiser = new Gson();
    return serialiser.toJson(msg);
  }

  public static GroupMessage deserializeMessage(String obj) {
    Gson serialiser = new Gson();
    return serialiser.fromJson(obj, GroupMessage.class);
  }
}