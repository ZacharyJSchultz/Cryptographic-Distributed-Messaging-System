package com.ciphersquad.chat.AuthenticationServer;

import java.io.Serializable;
import java.lang.reflect.Array;
import java.security.PublicKey;
import java.util.ArrayList;

import com.google.gson.Gson;


//for sending requests over the sockets
public class AuthRequest implements Serializable {
  private String username;
  private String password;
  private AuthType type;
  private Token token;
  private byte[] signature;
  private ArrayList<String> Members;
  private String groupName;
  private PublicKey clientPublicKey;
  private int client2ServerCounter;
  private byte[] hashedPK;

  public enum AuthType {
    LOGIN, REGISTER, DELETE, MAKE_GROUP, ADD_USER_TO_GROUP, REMOVE_USER_FROM_GROUP, LIST_GROUP, REMOVE_GROUP, GET_TOKEN, DH_KEY_EXCHANGE, GET_GROUP_KEYS
  }

  public AuthRequest(String username, String password, AuthType type) {
    this.username = username;
    this.password = password;
    this.type = type;
    this.clientPublicKey = null;
  }

  public AuthRequest(byte[] hashedPK, AuthType type){
    this.type = type;
    this.hashedPK = hashedPK;
  }

  public AuthRequest(String username, String password, AuthType type, ArrayList<String> Members) {
    // this constructor is for group chat operations
    this.username = username;
    this.password = password;
    this.type = type;
    this.Members = Members;
  }

  public AuthRequest(String username, String password, AuthType type, ArrayList<String> Members, String groupName) {
    // this constructor is for group chat operations
    this.username = username;
    this.password = password;
    this.type = type;
    this.Members = Members;
    this.groupName = groupName;
  }

  public AuthRequest(Token token, byte[] signature, AuthType type, String groupName) {
    // this constructor is for requesting all groupKeys
    this.token = token;
    this.signature = signature;
    this.type = type;
    this.groupName = groupName;
  }

  public AuthRequest(PublicKey key, AuthType type) {
    this.type = type;
    this.clientPublicKey = key;
  }
  

  public String getUsername() {
    return username;
  }

  public byte[] getHashedPK(){
    return hashedPK;
  }

  public String getPassword() {
    return password;
  }

  public AuthType getAuthType() {
    return type;
  }

  public ArrayList<String> getMembers() {
    return Members;
  }

  public String getGroupName() {
    return groupName;
  }

  public PublicKey getPublicKey() {
    return clientPublicKey;
  }

  public Token getToken() {
    return token;
  }

  public byte[] getSignature() {
    return signature;
  }

  public String toString() {
    Gson gson = new Gson();
    return gson.toJson(this);
  }

  public static AuthRequest fromString(String jsonString) {
    Gson gson = new Gson();
    return gson.fromJson(jsonString, AuthRequest.class);
  }
  
  public void setClient2ServerCounter(int counter) {
    this.client2ServerCounter = counter;
  }

  public int getClient2ServerCounter() {
    return this.client2ServerCounter;
  }
}
