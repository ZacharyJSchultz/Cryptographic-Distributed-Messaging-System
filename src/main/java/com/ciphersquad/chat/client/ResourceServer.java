package com.ciphersquad.chat.client;

import java.util.ArrayList;
import java.util.Scanner;

public class ResourceServer {
    int port;
    public ResourceServer() {
        port = -1;
    }
    public void updatePort(Scanner scanner) {
        System.out.println("\nPlease enter port number for resource server:");
        //make sure to check if the input is a number
        port = scanner.nextInt();
        return;
    }
    public boolean connect(User user) {
        //connect to the server
        return true;
    }
    public ArrayList<String> getConversations(User user) {
        // For now, return a dummy list of conversations
        ArrayList<String> conversations = new ArrayList<>();
        conversations.add("Conversation 1");
        conversations.add("Conversation 2");
        conversations.add("Conversation 3");
        return conversations;
    }
    public ArrayList<String> getMessages(User user, int conversationID) {
        // For now, return a dummy list of messages
        ArrayList<String> messages = new ArrayList<>();
        messages.add("Message 1");
        messages.add("Message 2");
        messages.add("Message 3");
        return messages;
    }
    public void sendMessage(User user, int conversationID, String message) {
        // Send the message
        return;
    }
}
