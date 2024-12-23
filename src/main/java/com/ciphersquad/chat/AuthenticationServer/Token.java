package com.ciphersquad.chat.AuthenticationServer;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class Token implements java.io.Serializable {
  private String username;
  private ArrayList<String> groupPermissions; // group -> permission mapping
  private Timestamp timestamp;
  private byte[] rsPubKey;

  public Token() {
    this.username = "";
    this.groupPermissions = new ArrayList<>();
  }

  public Token(String username, ArrayList<String> groupPermissions) {
    this.username = username;
    this.groupPermissions = groupPermissions;
    this.timestamp = new Timestamp(System.currentTimeMillis());
  }

  public String getUsername() {
    return username;
  }

  public ArrayList<String> getGroupPermissions() {
    return groupPermissions;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public void setGroupPermissions(ArrayList<String> groupPermissions) {
    this.groupPermissions = groupPermissions;
  }

  public void setRsPk(byte[] rsKey){
    this.rsPubKey = rsKey;
  }

  public Timestamp getTimestamp(){
    return this.timestamp;
  }

  public byte[] getRsPK(){
    return this.rsPubKey;
  }
}
