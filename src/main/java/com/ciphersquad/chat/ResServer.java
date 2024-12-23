package com.ciphersquad.chat;

import com.ciphersquad.chat.ResourceServer.RSKeyStorage;
import com.ciphersquad.chat.ResourceServer.RSThread;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.FileReader;
import java.io.IOException;

import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.HashSet;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

/**
 * Server Application that starts the server on dedicated port,
 * Each client will connect a to different Resource Server Thread.
 */
public class ResServer {

  public int serverPort; // Dedicated Port
  private ServerSocket serverSocket;
  private boolean keepRunning = true;
  private HashSet<RSThread> activeThreads = new HashSet<RSThread>();
  private String filePath = "./src/main/java/com/ciphersquad/chat/ResourceServer/RSKeys/rs_public_key.json";
  private PublicKey publicKey;
  private boolean reEncryptRequest;
  private long groupThreadID;
  private int reEncryptGroup;

  public static void main(String[] args) {
    try {
      new ResServer();
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace(System.err);
    }
  }

  /**
   * Server Setup
   */
  public ResServer() throws IOException {
    setPort();
    start();

  }

  /**
   * Main loop for the server.
   * Listens for client connecting to server, create new server thread as they
   * join
   * 
   */
  public void start() {
    Socket sock = null;
    RSThread thread = null;
    reEncryptRequest = false;
    groupThreadID = -1;
    reEncryptGroup = -1;
    // Shutdown hook

    Runtime.getRuntime().addShutdownHook(new Thread() {
      public void run() {
        keepRunning = false; // Stop RS from receiving new connections
        // int counter = 0;
        for (RSThread t : activeThreads) {
          t.interrupt();

          // System.err.println("Shutting down thread" + ++counter);
        }
        System.err.println("Resource Server Shutting Down.");
      }
    });

    // Thread Catching Re-encryption Request booting users out.
    Thread receiveThread = new Thread(new Runnable() {
      @Override
      public void run() {
        try {
          // If thread is interrupted, it will stop running
          while (!Thread.currentThread().isInterrupted()) {
            Thread.sleep(1000);
            if (reEncryptRequest) {
              reEncryptRequest = false;
              for (RSThread t : activeThreads) {
                if (t.groupID == reEncryptGroup && t.getId() != groupThreadID) {
                  t.interrupt();
                }
              }
              groupThreadID = -1;
              reEncryptGroup = -1;
            }
          }
        } catch (InterruptedException e) {
          System.out.println("Catch Thread Interrupted.");
        } catch (Exception e) {
          // e.printStackTrace();
          System.out.println("Uncaught Error for catch thread...");
        }
      }
    });
    receiveThread.start();
    while (keepRunning) { // Loop to accept multiple client
      try {
        sock = serverSocket.accept();
        thread = new RSThread(sock, publicKey, this);
        activeThreads.add(thread);
        thread.start();
      } catch (Exception e) {
        System.err.println("Error: " + e.getMessage());
        e.printStackTrace(System.err);
      }
    }
  }

  public void reEncryptGroup(long keepThread, int group) {
    groupThreadID = keepThread;
    reEncryptGroup = group;
    reEncryptRequest = true;
  }

  /**
   * Takes user input to create server port
   * 
   */
  private void setPort() {
    Scanner input = new Scanner(System.in);
    while (true) {
      System.out.println("Enter the IP that the server is hosted on: ");
      try {
        String serverIP = input.nextLine();
        if (readPublicKeys(serverIP)) {
          break;
        }
      } catch (Exception e) {
        System.out.println("Invalid IP, please try again.");
      }
    }
    while (true) {
      System.out.println("Enter the port number for the Resource Server: (Enter 0 for default port number)");
      try {
        serverPort = Integer.parseInt(input.nextLine());
        if (checkValidPort(serverPort)) {
          break;
        }
      } catch (Exception e) {
        System.out.println("Invalid port number, please try again.");
      }
    }
    System.err.println("Connecting to port number " + serverSocket.getLocalPort());
    input.close();
  }

  /**
   * Creates the serversocket for the RS if port is valid
   * 
   * @param port port number of the server
   * 
   */
  private boolean checkValidPort(int port) {
    try {
      serverSocket = new ServerSocket(serverPort);
    } catch (Exception e) {
      System.out.println("Invalid port number, please try again.");
      return false;
    }
    serverPort = serverSocket.getLocalPort();
    return true;
  }

  private boolean readPublicKeys(String serverIP) {
    Security.addProvider(new BouncyCastleProvider());
    try (FileReader r = new FileReader(filePath);) {
      Gson gson = new Gson();

      // Extract keys.json as JsonArray
      JsonArray arr = gson.fromJson(r, JsonArray.class);

      // For each (IP, PK) pair in keys.json, decode PK and store in mapping
      for (int i = 0; i < arr.size(); i++) {
        JsonObject obj = arr.get(i).getAsJsonObject();
        RSKeyStorage encodedPk = gson.fromJson(obj, RSKeyStorage.class);
        if (encodedPk.getServer().equals(serverIP)) {
          publicKey = KeyFactory.getInstance("RSA", "BC")
              .generatePublic(new X509EncodedKeySpec(encodedPk.getKey()));
          break;
        }
      }
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      System.err.println("Error reading public keys from file!");
      return false;
    }
  }
}
