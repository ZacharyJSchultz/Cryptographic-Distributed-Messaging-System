package com.ciphersquad.chat.ResourceServer;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.io.FileWriter;

import java.util.LinkedList;

public class Group implements java.io.Serializable {

  private int groupID;
  private LinkedList<GroupMessage> messageHistory;

  public Group(int groupID, LinkedList<GroupMessage> messageHistory) {
    this.groupID = groupID;
    this.messageHistory = messageHistory;
  }

  public Group() {
    this(-1, new LinkedList<GroupMessage>());
  }

  public Group(int groupID) {
    this(groupID, new LinkedList<GroupMessage>());
  }

  /**
   * Write the Message History of the group to Persistent Storage
   * 
   * @param resourceLocation The destination of the file for storage
   * @param isPM             Indication of whether the group is a PM session
   */
  public void SaveHistory(String resourceLocation, boolean isPM) {
    String paddedID = padID(this.groupID);
    if (isPM) {
      try (FileWriter writer = new FileWriter(resourceLocation + "P" + paddedID + ".json");) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(this, writer);
      } catch (IOException e) {
        System.out.println("something wrong");
      }
    } else {
      try (FileWriter writer = new FileWriter(resourceLocation + paddedID + ".json");) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        gson.toJson(this, writer);
      } catch (IOException e) {
        System.out.println("something wrong");
      }
    }
  }

  /**
   * Format the group ID for persistent storage
   * 
   * @param groupID The groupID to be padded into format
   */
  public static String padID(int groupID) {
    String ret = String.valueOf(groupID);
    for (int i = 4; i > ret.length(); ret = "0" + ret)
      ;
    return ret;
  }

  public void addMessage(GroupMessage m) {
    if (messageHistory.size() >= 20) {
      messageHistory.removeFirst();
    }
    messageHistory.add(m);
  }

  public int getGroupID() {
    return groupID;
  }

  public void setGroupID(int ID) {
    groupID = ID;
  }

  public LinkedList<GroupMessage> getHistory() {
    return messageHistory;
  }

  public void setHistory(LinkedList<GroupMessage> history) {
    messageHistory = new LinkedList<GroupMessage>();
    for (GroupMessage m : history) {
      messageHistory.add(m);
    }
  }
}
