package com.ciphersquad.chat.ResourceServer;

import com.ciphersquad.chat.ResServer;
import com.ciphersquad.chat.AuthenticationServer.ASKeypairGen;
import com.ciphersquad.chat.AuthenticationServer.Token;
import com.ciphersquad.chat.AuthenticationServer.TokenSerializer;

import java.io.IOException;
import java.io.ObjectInputStream; // For reading Java objects off of the wire
import java.io.ObjectOutputStream; // For writing Java objects to the wire
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.Thread; // We will extend Java's base Thread class
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.javatuples.Pair;

public class RSThread extends Thread {
  private final Socket socket;
  private final ObjectInputStream input;
  private final ObjectOutputStream output;
  private final PublicKey serverPubKey;
  private final ResServer rs;

  private static Hashtable<Integer, ServerSocket> groups = new Hashtable<Integer, ServerSocket>();
  private static Hashtable<Integer, ServerSocket> pmGroups = new Hashtable<Integer, ServerSocket>();

  // maybe setting up sqlite wasn't that bad of an idea
  // We got database at home :D, Database at home be like:
  private static Hashtable<Integer, ArrayList<String>> mapPMGroupUser = new Hashtable<Integer, ArrayList<String>>();
  private static Hashtable<String, ArrayList<Integer>> mapPMUserGroup = new Hashtable<String, ArrayList<Integer>>();
  // Online Users : Users Banned from Their PM session
  private static Hashtable<String, ArrayList<String>> activePMSession = new Hashtable<String, ArrayList<String>>();

  private static Lock countLock = new ReentrantLock();
  private static String pathName = "src/main/resource/"; // Path to chat history

  private String userName;
  private GroupThread newThread;
  private PrivateKey serverKey;
  public int groupID;

  private Cipher sessionCipher;
  private SecretKey sessionKey;
  private HMac hmac;
  private SecretKey hmacKey;

  private SecureRandom random;
  private int clientToServerCounter;
  private int serverToClientCounter;
  private RSMessages currWrapper;
  private GroupMessage groupMsg;

  /**
   * Communication thread between server and user
   * <p>
   * Handles Token authentication and group selection
   *
   * @param _socket The socket passed in from the server
   * @throws IOException Unexpected Error due to setting up IO stream to user
   */
  public RSThread(Socket _socket, PublicKey _serverPublicKey, ResServer _rs) throws IOException {
    Security.addProvider(new BouncyCastleProvider());
    socket = _socket;
    serverPubKey = _serverPublicKey;
    input = new ObjectInputStream(socket.getInputStream());
    output = new ObjectOutputStream(socket.getOutputStream());
    rs = _rs;
  }

  /**
   * Authentication Then Setup Connection
   *
   */
  @Override
  public void run() {
    try {
      System.out.println("** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + " **");

      // Authenticate User and Get Token
      String token = RSUserAuth();
      switch (token) {
        case "Invalid User Input":
          output.writeObject("Invalid User Input"); // Don't have a valid API built so might crash user
          closeConnection();
          return;
        case "Unexpected Failure":
          output.writeObject("Unexpected Server Side Error Happened, Closing Connection...");
          closeConnection();
          return;
        default: // All good
          break;
      }

      parseGroups(); // Read in groups from DB after valid authentication

      // token deserialise and parsing
      HashMap<Integer, Boolean> userPerm;
      try {
        userPerm = tokenParse(token);
      } catch (InvalidTokenException e) {
        output.writeObject("Token has expired, Closing Connection...");
        closeConnection();
        return;
      }

      // Authentication All Done FROM HERE ON
      // Intialize message counter, HMAC
      clientToServerCounter = 0;
      serverToClientCounter = 0;

      System.out.println("Authentication Complete, Sending Timestamp");
      output.writeObject(encryptMessage(String.valueOf(System.currentTimeMillis())));
      output.flush();

      while (connectionSetup(userPerm))
        ;

      closeConnection();
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
    }
  }

  /**
   * Clean Forced Shutdown of the Thread
   * 
   */
  @Override
  public void interrupt() {
    if (newThread != null) {
      newThread.interrupt();
    }
    try {
      closeConnection();
    } catch (IOException e) {
      e.printStackTrace();
    }
    super.interrupt();
  }

  /**
   * Close Connection for Thread Shutdown
   * 
   * @throws IOException
   */
  private void closeConnection() throws IOException {
    if (userName != null && activePMSession.contains(userName)) {
      activePMSession.remove(userName);
    }
    System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
    output.close();
    socket.close();
  }

  /**
   * Authentication Protocol for the Resource Server, Session Key Exchange
   * 
   * @param input  InputStream
   * @param output OutputStream
   * @return JSON string of the User Token or Error Messages
   */
  private String RSUserAuth() {
    try {
      // temp output stream for authentication

      // Get server private key
      BufferedInputStream keyIn = new BufferedInputStream(
          new FileInputStream("src/main/java/com/ciphersquad/chat/ResourceServer/RSKeys/rs_private_key.txt"));
      serverKey = KeyFactory.getInstance("RSA", "BC")
          .generatePrivate(new PKCS8EncodedKeySpec(keyIn.readAllBytes()));
      keyIn.close();
      // Decrypt User Nonce
      Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
      rsaCipher.init(Cipher.DECRYPT_MODE, serverKey);
      byte[] userNonce = rsaCipher.doFinal((byte[]) input.readObject());
      if (userNonce.length != 32) { // Checks whether userNonce is the proper size
        throw new InvalidKeyException("Invalid User Nonce");
      }
      random = SecureRandom.getInstance("DRBG"); // Secure random used for the session
      byte[] serverNonce = new byte[32];
      random.nextBytes(serverNonce);

      // Sign and Send Nonce
      Signature signer = Signature.getInstance("RSASSA-PSS", "BC");
      signer.initSign(serverKey);
      signer.update(serverNonce);
      byte[] serverNonceSignature = signer.sign();
      output.writeObject(new byte[][] { serverNonce, serverNonceSignature });
      output.flush();
      // generate session seed
      byte[] seed = new byte[32];
      for (int i = 0; i < seed.length; i++) {
        seed[i] = (byte) (serverNonce[i] ^ userNonce[i]);
      }

      // Session Key creation, send confirmation
      sessionCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC"); // AES Cipher for session
      byte[] firstIV = new byte[sessionCipher.getBlockSize()];
      random.nextBytes(firstIV);

      sessionKey = deriveAESKey(seed);
      hmacKey = deriveHMacKey(seed);
      hmac = new HMac(new SHA256Digest());
      hmac.init(new KeyParameter(hmacKey.getEncoded()));
      sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(firstIV));
      output.writeObject(new byte[][] { sessionCipher.doFinal("Session Key Established".getBytes()), firstIV });
      output.flush();

      byte[][] temp = (byte[][]) input.readObject();
      sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(temp[1]));
      byte[] tokenBytes = sessionCipher.doFinal(temp[0]);
      PublicKey ASPubKey = ASKeypairGen.loadPublicKey();
      signer = Signature.getInstance("SHA256withRSA/PSS", "BC");
      signer.initVerify(ASPubKey);
      signer.update(tokenBytes);
      if (!signer.verify(temp[2])) { // token failed to verify
        System.out.println("Verification Failed");
        throw new InvalidKeyException();  //TODO: comment
      }
      return new String(tokenBytes, StandardCharsets.UTF_8); // return token json string
      // return token;
    } catch (ClassCastException | InvalidKeyException e) {
      return "Invalid User Input";
    } catch (Exception e) {
      e.printStackTrace();
      return "Unexpected Failure";
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
  private String encryptMessage(String input)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    byte[] iv = new byte[sessionCipher.getBlockSize()];
    random.nextBytes(iv);
    serverToClientCounter++;
    GroupMessage msg = new GroupMessage(input.getBytes(), null, null, "Resource Server", -1,
        serverToClientCounter, false);
    sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
    byte[] ciphertext = sessionCipher.doFinal(GroupMessage.serializeMessage(msg).getBytes());
    hmac.update(ciphertext, 0, ciphertext.length);
    byte[] hmacResult = new byte[hmac.getMacSize()];
    hmac.doFinal(hmacResult, 0);
    return RSMessages.serializeMessage(
        new RSMessages(ciphertext, iv, "Resource Server", hmacResult));
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
   * @throws InvalidTokenException
   */
  private void decryptMessage(String input)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
      InvalidHMACException, InvalidTokenException {
    clientToServerCounter++;
    currWrapper = RSMessages.deserializeMessage(input);
    hmac.update(currWrapper.getMessage(), 0, currWrapper.getMessage().length);
    byte[] hmacResult = new byte[hmac.getMacSize()];
    hmac.doFinal(hmacResult, 0);
    if (!Arrays.equals(hmacResult, currWrapper.getHMAC()))
      throw new InvalidHMACException();
    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(currWrapper.getIV()));
    groupMsg = GroupMessage
        .deserializeMessage(new String(sessionCipher.doFinal(currWrapper.getMessage()), StandardCharsets.UTF_8));
    if (groupMsg.getCounter() != clientToServerCounter) {
      throw new InvalidHMACException(); // Name is confusing but its the same case, message was tampered
    }
  }

  /**
   * 
   * @param token JSON string of user token
   * @return HashMap of the permission if successful; null if unexpected error
   *         Happened
   * @throws InvalidTokenException    Token Expired
   * @throws NoSuchAlgorithmException
   */
  private HashMap<Integer, Boolean> tokenParse(String token) throws InvalidTokenException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    Token t = TokenSerializer.deserializeToken(token);

    // Check timestamp validity
    if ((t.getTimestamp().getTime() + TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES)) < System
        .currentTimeMillis()) { // currentime within 5 minutes
      throw new InvalidTokenException();
    }

    // Check public key hash
    byte[] hashedKey = digest.digest(serverPubKey.getEncoded());
    if (!Arrays.equals(t.getRsPK(), hashedKey)) {
      throw new InvalidTokenException();
    }

    userName = t.getUsername();
    String perm;
    HashMap<Integer, Boolean> groupPerm = new HashMap<Integer, Boolean>();
    activePMSession.put(userName, new ArrayList<String>());
    for (String g : t.getGroupPermissions()) { // Parse User Group Permissions
      if (g.substring(4).toUpperCase().equals("D")) {
        deleteGroup(Integer.valueOf(g.substring(0, 4)));
        continue;
      }
      perm = (g.substring(4).toUpperCase().equals("A")) ? "true" : "false";
      groupPerm.put(Integer.valueOf(g.substring(0, 4)), Boolean.parseBoolean(perm));
    }
    try {
      countLock.lock();
      for (int groupNo : groupPerm.keySet()) { // Create new group if necessary
        if (!groups.keySet().contains(groupNo)) {
          try {
            groups.put(groupNo, new ServerSocket(0));
          } catch (IOException e) {
            countLock.unlock();
            e.printStackTrace();
            return null;
          }
        }
      }
    } finally {
      countLock.unlock();
    }
    return groupPerm;
  }

  /**
   * Main Loop for connecting user to the groups
   * 
   * @param userPerm Permission of the users for accessing groups
   * @return continue connection or not
   */
  private boolean connectionSetup(HashMap<Integer, Boolean> userPerm) {
    // while (true){
    try {
      Pair<Integer, Boolean> selectionRes = groupSelection(output, input, userPerm);
      int ID = selectionRes.getValue0();
      boolean isPM = selectionRes.getValue1();

      if (ID == -2) {
        closeConnection();
        return false;
      }

      int port = (isPM) ? pmGroups.get(ID).getLocalPort() : groups.get(ID).getLocalPort();
      System.out.println("Port: " + port);
      output.writeObject(encryptMessage(String.valueOf(port)));
      output.flush();

      Socket newSock = null;
      if (isPM) {
        newSock = pmGroups.get(ID).accept();
        groupID = ID;
        newThread = new GroupThread(newSock, ID, userName, false, true, sessionKey, hmacKey, this.getId(), rs);
      } else {
        newSock = groups.get(ID).accept();
        groupID = ID;
        newThread = new GroupThread(newSock, ID, userName, userPerm.get(ID), false, sessionKey, hmacKey, this.getId(),
            rs);
      }

      newThread.start();
      while (newThread.isAlive())
        ;

      // Thread Teardown
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  /**
   * Server side of user selecting groups to join
   *
   * @param output    Output stream for the socket, Server -> User
   * @param input     Input stream for the socket, Server <- User
   * @param groupPerm The user's group permissions, identifies asoociated groups
   *
   * 
   */
  private Pair<Integer, Boolean> groupSelection(ObjectOutputStream output, ObjectInputStream input,
      HashMap<Integer, Boolean> groupPerm) {

    StringBuilder availableGroups = new StringBuilder();
    for (Integer i : groupPerm.keySet())
      availableGroups.append(i + " ");
    String msg = "";

    try {
      output.writeObject(encryptMessage(availableGroups.toString()));
      output.flush();
      do {
        try {
          decryptMessage((String) input.readObject());
          msg = new String(groupMsg.getMessage()); // group number intended to join

          // If equals exit or PM, handle that
          if (msg.toLowerCase().equals("pm")) {
            return pmSelection(output, input, groupPerm);
          }
          if (msg.equals("exit")) {
            return new Pair<Integer, Boolean>(-2, false);
          }
          if (!groupPerm.keySet().contains(Integer.valueOf(msg))) {
            throw new InvalidSelectionException(); // Custom Exception
          }
          return new Pair<Integer, Boolean>(Integer.valueOf(msg), false);
        } catch (InvalidHMACException e) {
          output.writeObject(encryptMessage("Message Tampering detected, disconnecting..."));
          output.flush();
          return new Pair<Integer, Boolean>(-2, true);
        } catch (InvalidSelectionException | NumberFormatException | ClassCastException e) {
          //e.printStackTrace();
          output.writeObject(encryptMessage("Invalid Group Number, try again"));
          output.flush();
        }
      } while (true);
    } catch (Exception e) {
      return new Pair<Integer, Boolean>(-2, false);
    }
  }

  /**
   * Server side of user selecting users for private messaging
   *
   * @param output    Output stream for the socket, Server -> User
   * @param input     Input stream for the socket, Server <- User
   * @param groupPerm The user's group permissions, identifies asoociated groups
   * @throws InvalidAlgorithmParameterException
   *
   */
  private Pair<Integer, Boolean> pmSelection(ObjectOutputStream output, ObjectInputStream input,
      HashMap<Integer, Boolean> groupPerm) {
    StringBuilder availableGroups = new StringBuilder();
    for (String u : activePMSession.keySet()) {
      if (!activePMSession.get(u).contains(this.userName) && !u.equals(userName)) {
        availableGroups.append(u + " ");
      }
    }
    String msg = "";
    try {
      output.writeObject(encryptMessage(availableGroups.toString()));
      output.flush();
      do {
        try {
          decryptMessage((String) input.readObject());
          msg = new String(groupMsg.getMessage());
          // If equals exit or PM, handle that
          if (msg.equals("exit")) {
            return new Pair<Integer, Boolean>(-2, true);
          }
          if (msg.equals("~back")) {
            return groupSelection(output, input, groupPerm);
          }
          // Target not online or user is banned
          if (!activePMSession.keySet().contains(msg) || activePMSession.get(msg).contains(userName)) {
            throw new InvalidSelectionException();
          }
          // If pm session not active, create new pm session
          if (!mapPMUserGroup.containsKey(msg)) {
            int newPMNo = generatePMID();
            pmGroupGeneration(msg, newPMNo);
            return new Pair<Integer, Boolean>(newPMNo, true);
          }
          // Get pm session if it exists
          for (int i : mapPMUserGroup.get(msg)) {
            if (mapPMGroupUser.get(i).contains(userName)) {
              return new Pair<Integer, Boolean>(i, true);
            }
          }

        } catch (InvalidHMACException e) {
          output.writeObject(encryptMessage("Message Tampering detected, disconnecting..."));
          output.flush();
          return new Pair<Integer, Boolean>(-2, true);
        } catch (InvalidSelectionException | ClassCastException e) {
          output.writeObject(encryptMessage("Invalid user, try again"));
          output.flush();
        }
      } while (true);
    } catch (Exception e) {
      return new Pair<Integer, Boolean>(-2, true);
    }
  }

  /**
   * @param targetUser The other user that is being added to the session
   * @param pmID
   * @return True or False depending on whether the operation was successful
   */
  private boolean pmGroupGeneration(String targetUser, int pmID) {
    ArrayList<String> newGroupMember = new ArrayList<String>();
    ArrayList<Integer> userToGroup = new ArrayList<Integer>();
    newGroupMember.add(userName);
    newGroupMember.add(targetUser);
    userToGroup.add(pmID);

    try {
      countLock.lock();
      pmGroups.put(Integer.valueOf(pmID), new ServerSocket(0));
      mapPMGroupUser.put(pmID, new ArrayList<String>(newGroupMember));
      mapPMUserGroup.put(userName, new ArrayList<Integer>(userToGroup));
    } catch (Exception e) {
      return false;
    } finally {
      countLock.unlock();
    }
    return true;
  }

  /**
   * Delete Group History Requested by the Token, Close Open Connection
   * 
   * @param groupID The Group Number Requested to be deleted
   */
  private boolean deleteGroup(int groupID) {
    try {
      groups.get(groupID).close();
      groups.remove(groupID);
    } catch (Exception e) {
      e.printStackTrace();
    }
    File groupHistory = new File(pathName + Group.padID(groupID) + ".json");
    return groupHistory.delete();

  }

  /**
   * Generates a new PM session ID
   * 
   */
  private int generatePMID() {
    Random rand = new Random();
    int ret;
    do {
      ret = rand.nextInt(10000);
    } while (pmGroups.keySet().contains(ret));
    return ret;
  }

  /**
   * Generate Key for AES
   * 
   * @param sharedSecret
   * @return 256 Bit AES Key
   */
  private SecretKeySpec deriveAESKey(byte[] sharedSecret) {
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(sharedSecret, null, null));
    byte[] aesKey = new byte[32]; // 256 bits
    hkdf.generateBytes(aesKey, 0, aesKey.length);
    return new SecretKeySpec(aesKey, "AES");
  }

  /**
   * Generate key for HMAC
   * 
   * @param sharedSecret
   * @return 256 Bit HMAC Key
   */
  private SecretKeySpec deriveHMacKey(byte[] sharedSecret) {
    byte[] modifiedSecret = new byte[sharedSecret.length];
    for (int i = 0; i < sharedSecret.length; i++) {
      modifiedSecret[i] = (byte) (sharedSecret[i] ^ 'h');
    }
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(modifiedSecret, null, null));
    byte[] hmacKey = new byte[32]; // 256 bits
    hkdf.generateBytes(hmacKey, 0, hmacKey.length);
    return new SecretKeySpec(hmacKey, "HmacSHA256");
  }

  /**
   * Reads in groups from database
   * 
   * @throws IOException Unexpected error that should never happen
   */
  private void parseGroups() throws IOException {
    try {
      // Reads in group history files to create ports for existing groups
      File folder = new File(pathName);
      File[] listOfFiles = folder.listFiles();

      // Get all groups then assign them ports if needed
      countLock.lock();
      for (File file : listOfFiles) {
        String name = file.getName();
        if (name.equals(".DS_Store") || name.equals(".empty") || !file.isFile()) {
          continue;
        }
        if (name.substring(0, 1).equals("P")) {
          int pmID = Integer.valueOf(name.substring(1, name.indexOf(".")));
          if (!pmGroups.containsKey(pmID)) {
            pmGroups.put(pmID, new ServerSocket(0));
          }
        } else {
          int groupID = Integer.valueOf(name.substring(0, name.indexOf(".")));
          if (!groups.containsKey(groupID)) {
            groups.put(groupID, new ServerSocket(0));
          }
        }

      }
    } catch(Exception e) {
      System.err.println("Error parsing group file! Continuing...");
    } finally {
      countLock.unlock();
    }

  }
}
// -- end class RSThread