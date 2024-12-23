package com.ciphersquad.chat.ResourceServer;

import com.ciphersquad.chat.ResServer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire
import java.io.FileReader;
import java.io.FileNotFoundException;

import java.net.Socket;
import java.nio.charset.StandardCharsets;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.LinkedList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread {
  private final Socket socket;
  private final int groupID;
  private final String userName;
  private final boolean permission; // true for admin, false for non-admin
  private final boolean isPM;
  private final SecretKey sessionKey;
  private final SecretKey hmacKey;
  private final long parentID;
  private final ResServer rs;
  private SecureRandom random;
  private Cipher sessionCipher;
  private HMac hmac;
  private Group currentGroup;
  private RSMessages currWrapper;
  private GroupMessage groupMsg;

  private static String pathName = "src/main/resource/";
  private static Hashtable<String, ObjectOutputStream> users = new Hashtable<String, ObjectOutputStream>();
  private static Hashtable<String, SecretKey> userKeys = new Hashtable<String, SecretKey>();
  private static Hashtable<String, SecretKey> userHMacKeys = new Hashtable<String, SecretKey>();
  private static Hashtable<String, Integer> userServerCounter = new Hashtable<String, Integer>();
  private static Hashtable<String, Integer> serverUserCounter = new Hashtable<String, Integer>();
  private static Lock countLock = new ReentrantLock();

  /**
   * Communication thread between group and user
   *
   * @param _socket     The socket passed in from the server
   * @param _groupID    The group ID to be connected to
   * @param _userName   User to be connected
   * @param _permission The permission level of the user in the group
   * @param _isPM       Whether the current group is a PM group
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   *
   */
  public GroupThread(Socket _socket, int _groupID, String _userName, boolean _permission, boolean _isPM,
      SecretKey _sessionKey, SecretKey _hmacKey, long _parentID, ResServer _rs)
      throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
    // Read in group history and deserialise
    Security.addProvider(new BouncyCastleProvider());
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    groupID = _groupID;
    userName = _userName;
    permission = _permission;
    isPM = _isPM;
    sessionKey = _sessionKey;
    hmacKey = _hmacKey;
    parentID = _parentID;
    rs = _rs;
    FileReader reader = null;
    try {
      if (isPM) {
        reader = new FileReader(pathName + "P" + Group.padID(groupID) + ".json");
      } else {
        reader = new FileReader(pathName + Group.padID(groupID) + ".json");
      }
      currentGroup = gson.fromJson(reader, Group.class);
    } catch (FileNotFoundException e) {
      currentGroup = new Group(groupID);
    } catch (Exception e) {
      currentGroup = new Group(groupID);
    }
    socket = _socket;
    random = SecureRandom.getInstance("DRBG");
    sessionCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
    hmac = new HMac(new SHA256Digest());
    hmac.init(new KeyParameter(hmacKey.getEncoded()));
  }

  /**
   * Run the Thread, Received message from connection client and broadcast through
   * the socket
   * 
   */
  @Override
  public void run() {
    try {
      System.out.println("** New connection to Group from " + userName + " and " + permission + " admin **");

      users.put(userName, new ObjectOutputStream(socket.getOutputStream()));
      userKeys.put(userName, sessionKey);
      userHMacKeys.put(userName, hmacKey);
      userServerCounter.put(userName, 0);
      serverUserCounter.put(userName, 0);
      final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

      // Loop to read messages
      int noMessages = currentGroup.getHistory().size();
      users.get(userName).writeObject(encryptMessage(String.valueOf(currentGroup.getHistory().size()), userName));
      for (GroupMessage msg : currentGroup.getHistory()) {
        users.get(userName).writeObject(encryptMessage(msg, userName));
      }
      // |> from Elixir to Java when?
      // Synatatic Dumpsterfire
      users.get(userName)
          .writeObject(encryptMessage("End of Group History", userName));

      do {
        // read and print message
        decryptMessage((String) input.readObject());
        if (groupMsg.getMessageStr().equals("Re-en req")) {
          currentGroup.setHistory(new LinkedList<>()); // Clear History of old Messages
          for (int i = 0; i < noMessages; i++) {
            decryptMessage((String) input.readObject());
            System.out.println(groupMsg.getMessage() + " | " + groupMsg.getSender());
            currentGroup.addMessage(groupMsg);
            /*users.entrySet()
                .forEach(entry -> {
                  try {
                    entry.getValue().writeObject(
                        encryptMessage("Message Re-encryption, please re-authenticate with Auth Server.",
                            entry.getKey()));
                  } catch (Exception e) {
                    e.printStackTrace();
                    return;
                  }
                });*/
          }
          rs.reEncryptGroup(parentID, groupID);
          Thread.sleep(5000); // Wait till other threads are booted
          System.out
              .println(
                  "** Closing connection with on Group Thread " + socket.getInetAddress() + ":"
                      + socket.getPort()
                      + " **");
          interrupt();
        } else {
          if (!groupMsg.getMessageStr().toUpperCase().equals("~BACK")) {
            currentGroup.addMessage(groupMsg);
            final String sender = groupMsg.getSender();
            final String msg = groupMsg.getMessageStr();
            System.out.println("[" + sender + ":" + socket.getPort() + "] " + msg);
            users.entrySet()
                .forEach(entry -> {
                  try {
                    entry.getValue().writeObject(encryptMessage(groupMsg, entry.getKey()));
                  } catch (Exception e) {
                    e.printStackTrace();
                    return;
                  }
                });
          }
        }
        //
      } while (!groupMsg.getMessageStr().toUpperCase().equals("~BACK"));
      System.out
          .println(
              "** Closing connection with on Group Thread " + socket.getInetAddress() + ":" + socket.getPort() + " **");
      interrupt();
    } catch (InvalidHMACException e) {
      System.out.println("Message Tampered, returning.");
      System.out
          .println(
              "** Closing connection with on Group Thread " + socket.getInetAddress() + ":" + socket.getPort() + " **");
      interrupt();
      return;
    } catch (Exception e) {
      e.printStackTrace();
      return;
    }
  }

  /**
   * Clean Shutdown of the Thread
   * 
   */
  @Override
  public void interrupt() {
    try {
      countLock.lock();
      currentGroup.SaveHistory(pathName, isPM);
      try {
        users.get(userName).close();
      } catch (Exception e) {
      }
      users.remove(userName);
      userKeys.remove(userName);
    } finally {
      countLock.unlock();
      super.interrupt();
    }
  }

  /**
   * 
   * @param input String to be Encrypted
   * @return Encrypted Message and IV
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InvalidAlgorithmParameterException
   */
  private String encryptMessage(String input, String toUser)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    byte[] iv = new byte[sessionCipher.getBlockSize()];
    serverUserCounter.put(toUser, serverUserCounter.get(toUser) + 1);
    random.nextBytes(iv);
    GroupMessage msg = new GroupMessage(input.getBytes(), null, null, "Resource Server", -1,
        serverUserCounter.get(toUser), false);

    sessionCipher.init(Cipher.ENCRYPT_MODE, userKeys.get(toUser), new IvParameterSpec(iv));
    byte[] ciphertext = sessionCipher.doFinal(GroupMessage.serializeMessage(msg).getBytes());
    hmac.update(ciphertext, 0, ciphertext.length);
    byte[] hmacResult = new byte[hmac.getMacSize()];
    hmac.doFinal(hmacResult, 0);
    return RSMessages.serializeMessage(
        new RSMessages(ciphertext, iv, "Resource Server", hmacResult));
  }

  /**
   * 
   * @param input String to be Encrypted
   * @return Encrypted Message and IV
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InvalidAlgorithmParameterException
   */
  private String encryptMessage(GroupMessage input, String toUser)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    byte[] iv = new byte[sessionCipher.getBlockSize()];
    // serverUserCounter.put(toUser, serverUserCounter.get(toUser) + 1);
    // input.setCounter(serverUserCounter.get(toUser));
    random.nextBytes(iv);
    sessionCipher.init(Cipher.ENCRYPT_MODE, userKeys.get(toUser), new IvParameterSpec(iv));
    byte[] ciphertext = sessionCipher.doFinal(GroupMessage.serializeMessage(input).getBytes());
    hmac.init(new KeyParameter(userHMacKeys.get(toUser).getEncoded()));
    hmac.update(ciphertext, 0, ciphertext.length);
    byte[] hmacResult = new byte[hmac.getMacSize()];
    hmac.doFinal(hmacResult, 0);
    return RSMessages.serializeMessage(
        new RSMessages(ciphertext, iv, input.getSender(), hmacResult));
  }

  /**
   * 
   * @param input AES encrypted Message and IV
   * @return Decrypted input
   * @throws InvalidKeyException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws InvalidHMACException
   */
  private void decryptMessage(String input)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
      InvalidHMACException {

    currWrapper = RSMessages.deserializeMessage(input);
    userServerCounter.put(currWrapper.getSender(), serverUserCounter.get(currWrapper.getSender()) + 1);
    hmac.init(new KeyParameter(userHMacKeys.get(currWrapper.getSender()).getEncoded()));
    hmac.update(currWrapper.getMessage(), 0, currWrapper.getMessage().length);
    byte[] hmacResult = new byte[hmac.getMacSize()];
    hmac.doFinal(hmacResult, 0);
    if (!Arrays.equals(hmacResult, currWrapper.getHMAC()))
      throw new InvalidHMACException();
    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(currWrapper.getIV()));
    groupMsg = GroupMessage
        .deserializeMessage(new String(sessionCipher.doFinal(currWrapper.getMessage()), StandardCharsets.UTF_8));
    /*
     * if (groupMsg.getCounter() != userServerCounter.get(groupMsg.getSender())) {
     * throw new InvalidHMACException(); // Name is confusing but its the same case,
     * message was tampered
     * }
     */
  }
}