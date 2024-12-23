package com.ciphersquad.chat.AuthenticationServer;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import org.javatuples.Pair;

import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import com.google.gson.Gson;

import java.security.PublicKey;
import javax.crypto.SecretKey;

//sending responses over socket
public class AuthResponse implements Serializable {
  private boolean success;
  private String message;
  private int groupID;
  private String token;
  private HashMap<Integer, byte[][]> secretKeys;   // id -> { encoded(SecretKey), version }
  private List<byte[]> groupKeys;
  private byte[] signature;
  private PublicKey serverPublicKey;
  private byte[] iv;
  private int server2ClientCounter;


  public AuthResponse(boolean success, String message, String token) {
    this.success = success;
    this.message = message;
    this.token = token;
    this.serverPublicKey = null;
    this.iv = null;
  }

  // Provides user with keys for all the groups they are in, as well as the version number of the key (so they can check if they need a different version)
  public AuthResponse(boolean success, String message, String token, HashMap<Integer, byte[][]> key, byte[] signature){
    this.success = success;
    this.message = message;
    this.token = token;
    this.secretKeys = key;
    this.signature = signature;
  }

  // Provides user with all past groupKeys for a single group
  public AuthResponse(boolean success, int groupID, List<byte[]> keys){
    this.success = success;
    this.groupID = groupID;
    this.groupKeys = keys;
  }

  public AuthResponse(PublicKey key, byte[] signature) {
    this.serverPublicKey = key;
    this.success = true;
    this.message = null;
    this.token = null;
    this.iv = null;
    this.signature = signature;
  }

  public AuthResponse(byte[] iv) {
    this.iv = iv;
    this.success = true;
    this.message = null;
    this.token = null;
    this.serverPublicKey = null;
  }

  public boolean isSuccessful() {
    return success;
  }

  public String getMessage() {
    return message;
  }

  public String getToken() {
    return token;
  }

  public int getGroupID() {
    return groupID;
  }

  public HashMap<Integer, byte[][]> getSecretKeys() {
    return secretKeys;
  }

  public PublicKey getPublicKey() {
    return serverPublicKey;
  }

  // Returns all past keys for a given group (if included in response)
  public List<byte[]> getAllGroupKeys() {
    return groupKeys;
  }

  public byte[] getIV() {
    return iv;
  }

  public String toString() {
    Gson gson = new Gson();
    return gson.toJson(this);
  }
  
  public static AuthResponse fromString(String jsonString) {
    Gson gson = new Gson();
    return gson.fromJson(jsonString, AuthResponse.class);
  }

  public byte[] getSignature(){
    return this.signature;
  }

  public void setServer2ClientCounter(int counter){
    this.server2ClientCounter = counter;
  }

  public int getServer2ClientCounter(){
    return this.server2ClientCounter;
  }
}