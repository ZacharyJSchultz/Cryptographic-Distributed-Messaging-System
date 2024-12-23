package com.ciphersquad.chat.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.net.Socket;
import java.net.SocketException;
import java.lang.InterruptedException;
import java.sql.Timestamp;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;

import org.javatuples.Pair;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ciphersquad.chat.App;
import com.ciphersquad.chat.ResourceServer.GroupMessage;
import com.ciphersquad.chat.ResourceServer.InvalidHMACException;
import com.ciphersquad.chat.AuthenticationServer.TokenSerializer;
import com.ciphersquad.chat.ResourceServer.RSMessages;

public class ResourceServerApp {
  private User user;
  private Scanner scanner;
  private int group_id;
  private int port;
  private int RSport; // default port for RS (inputted by user)
  private int clientToServerCounter, serverToClientCounter;
  private int clientToServerGroupCounter, serverToClientGroupCounter;
  private Socket rsSocket;
  private Socket groupSocket;
  private ObjectInputStream rsInput;
  private ObjectOutputStream rsOutput;
  private ObjectInputStream groupInput;
  private ObjectOutputStream groupOutput;
  private final boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
  private SecretKey sessionKey;
  private SecretKey hmacKey;
  private HMac hmac;
  private SecureRandom r;

  public ResourceServerApp(User user, Scanner scanner) {
    Security.addProvider(new BouncyCastleProvider());
    this.user = user;
    this.scanner = scanner;
    this.group_id = -1;
    this.port = -1;
    this.RSport = -1;
    this.groupSocket = null;
    this.hmac = new HMac(new SHA256Digest());
  }

  private enum rsAppScreen {
    CHOOSE_RS, CONNECT_AND_PROTOCOL, CHOOSE_GROUP, CONNECT_GROUP, PM, CONVERSATION, EXIT, RE_ENCRYPT
  }

  public Screen run() {
    System.out.println("\n\nWelcome to Resource Server App");
    rsAppScreen currentScreen = rsAppScreen.CHOOSE_RS;
    while (true) {
      switch (currentScreen) {
        case CHOOSE_RS:
          currentScreen = chooseRS();
          break;

        case CONNECT_AND_PROTOCOL:
          currentScreen = connectAndProtocol();
          break;

        case CHOOSE_GROUP:
          currentScreen = chooseGroup();
          break;

        case CONNECT_GROUP:
          currentScreen = connectToGroup();
          break;

        case PM:
          currentScreen = privateMessage();
          break;

        case CONVERSATION:
          currentScreen = conversation();
          break;

        case EXIT:
          return Screen.LOGIN;

        default:
          System.out.println("Unknown screen");
          return Screen.EXIT;
      }
    }
  }

  // Function to choose the resource server the user wants to connect to, and
  // connects to it
  private rsAppScreen chooseRS() {
    try {
      this.clientToServerCounter = 0;
      this.serverToClientCounter = 0;

      System.out.println(
          "\nEnter the port # of the resource server you would like to join (Type '-1' to return to the login screen):");
      this.RSport = scanner.nextInt();
      scanner.nextLine(); // Consume newline character

      if(this.RSport == -1)
        return rsAppScreen.EXIT;
      
    } catch (Exception e) {
      scanner.nextLine(); // Consume newline character
      System.out.println("Error! Invalid input!");
      return rsAppScreen.CHOOSE_RS;
    }

    return rsAppScreen.CONNECT_AND_PROTOCOL;
  }

  private rsAppScreen connectAndProtocol() {
    try {
      rsSocket = new Socket(App.ip, RSport);

      // Socket I/O
      rsOutput = new ObjectOutputStream(rsSocket.getOutputStream());
      rsInput = new ObjectInputStream(rsSocket.getInputStream());

      int protocolResult = verificationProtocol();

      // 0 = success, 1 = no pk, 2 = signature fail, 3 = wrong message from server, 4
      // = invalid timestamp, 5 = exception
      if (protocolResult != 0) {
        switch (protocolResult) {
          case 1 -> System.err.println("Error! No public key for this server found.");
          case 2 -> System.err.println("Error! Incorrect handshake signature received from RS.");
          case 3 -> System.err.println("Error! Invalid handshake message received from RS.");
          case 4 -> {
            System.err.println("Error! The token has expired.");
            return rsAppScreen.EXIT; // If token is expired, exit and revalidate token
          }
          case 5 -> System.err.println("Error validating with specified resource server!");
        }
        return rsAppScreen.CHOOSE_RS; // Return to choose RS screen if failure in protocol
      }

      return rsAppScreen.CHOOSE_GROUP;
    } catch (Exception e) {
      System.err.println("Error: Invalid IP or port #. Please try again!");
      // //e.printStackTrace();
      closeEverything(false);
      return rsAppScreen.CHOOSE_RS;
    }
  }

  // Function to select the group and connect to it
  private rsAppScreen chooseGroup() {
    try {
      GroupMessage groupList = decrypt((String) rsInput.readObject(), false, false, ++serverToClientCounter); // List of group ids to print

      do {
        System.out.println(
            "\nPlease enter the ID of the group you would like to join! For reference, here's a list of current groups: "
                + groupList.getMessageStr());
        System.out.println(
            "\nAlternatively, if you would like to Private Message another online user, please enter 'PM'. If you'd like to exit the resource server, please type 'exit'!\n");

        // Input loop to get valid response (must be int >= 0 or 'exit' or 'PM' to be
        // valid)
        String clientResponse = "";
        try {
          clientResponse = scanner.nextLine().toUpperCase();
          if (clientResponse.equals("PM"))
            return rsAppScreen.PM;
          else if (clientResponse.equals("EXIT")) {
            rsOutput.writeObject(encrypt("exit", true, ++clientToServerCounter));
            closeEverything(false);
            return rsAppScreen.CHOOSE_RS;
          }
          group_id = Integer.valueOf(clientResponse);

          // Throw exception if invalid group, printing error message and continuing loop
          if (group_id < 0)
            throw new NumberFormatException();
        } catch (NumberFormatException e) {
          System.err.println("Invalid input. Please try again!");
          continue;
        }

        rsOutput.writeObject(encrypt(String.valueOf(group_id), true, ++clientToServerCounter)); // Write user's desired group_id to RS
        rsOutput.flush();

        try {
          // If message != a valid int, then going to assume it is invalid
          GroupMessage portBytes = decrypt((String) rsInput.readObject(), false, false, ++serverToClientCounter);
          this.port = Integer.valueOf(portBytes.getMessageStr());
        } catch (ClassCastException e) {
          System.err.println("\nError converting port # sent by RS.");
        } catch (IOException e) {
          //e.printStackTrace();
          System.err.println("\nError! You do not have permission to view this group.");

          rsInput.readObject(); // Flush error from RS
        }
      } while (group_id <= 0 || port <= 0);
      return rsAppScreen.CONNECT_GROUP;
    } catch (Exception e) {
      System.err.println("\nError connecting to Resource Server! Please try again!");
      closeEverything(false);
      return rsAppScreen.CHOOSE_RS;
    }
  }

  // Connects to the port representing the specific group / PM
  private rsAppScreen connectToGroup() {
    try {
      // If response is a valid port #, then connect to it
      groupSocket = new Socket(App.ip, port);

      groupInput = new ObjectInputStream(groupSocket.getInputStream());
      groupOutput = new ObjectOutputStream(groupSocket.getOutputStream());

      return rsAppScreen.CONVERSATION;
    } catch (Exception e) {
      System.err.println("\nError connecting to group " + group_id + "! Please try again!");
      closeEverything(true);
      return rsAppScreen.CHOOSE_GROUP;
    }
  }

  private rsAppScreen privateMessage() {
    try {
      /*
       * Steps:
       * - Client writes 'PM' to RS, informing them that it would like to private
       * message
       * - RS sends back list of online users for client to select from
       * - Client sends the user it would like to chat with to the RS
       * - RS sets up / opens a group with the two of them, sending back the port for
       * the client to connect to
       */
      rsOutput.writeObject(encrypt("PM", true, ++clientToServerCounter));
      rsOutput.flush();

      GroupMessage usersList = decrypt((String) rsInput.readObject(), false, false, ++serverToClientCounter);
      System.out.println(
          "\nPlease enter the name of the user you would like to PM with (or enter ~back to go back)! Here is a list of all currently online users: "
              + usersList.getMessageStr());

      String selectedUser = scanner.nextLine();
      rsOutput.writeObject(encrypt(selectedUser, true, ++clientToServerCounter));
      rsOutput.flush();

      if (selectedUser.equals("~back")) {
        System.out.println("\nReturning...\n");
        closeEverything(true);
        return rsAppScreen.CHOOSE_GROUP;
      }

      try {
        // If message != a valid int, then going to assume it is invalid
        GroupMessage portBytes = decrypt((String) rsInput.readObject(), false, false, ++serverToClientCounter);
        this.port = Integer.valueOf(portBytes.getMessageStr());
      } catch (IOException e) {
        System.err.println("\nError: Invalid user!");
        rsInput.readObject(); // Flush error from RS
        return rsAppScreen.CHOOSE_GROUP;
      }

      return rsAppScreen.CONNECT_GROUP;
    } catch (Exception e) {
      scanner.nextLine();
      System.err.println("\nError initializing Private Message! Please try again!");
      return rsAppScreen.CHOOSE_GROUP;
    }
  }

  // Talk in / Read from group chat
  private rsAppScreen conversation() {
    try {
      this.clientToServerGroupCounter = 0;
      this.serverToClientGroupCounter = 0;

      GroupMessage noHist = decrypt((String) groupInput.readObject(), false, true, ++serverToClientGroupCounter);
      int noMessages = Integer.valueOf(noHist.getMessageStr());

      if (user.needsReencryption && user.reencryptionGroup == group_id) {
        List<String> messages = reEncrypt(noMessages, groupInput);
        if (messages == null){
          System.out.println("Re-encryption failed");
          closeEverything(true);
          return rsAppScreen.CHOOSE_GROUP;
        }
        // writes "Re-en req " followed by no. of messages then group id to RS to
        // indicate a re-encryption request
        groupOutput.writeObject(encrypt("Re-en req", true, ++clientToServerGroupCounter));
        groupOutput.flush();
        // then sends each message, already in encrypted RSMessages format
        for (String message : messages) {
          groupOutput.writeObject(message);
          groupOutput.flush();
        }
        user.needsReencryption = false;
        System.out.println("Re-encryption request sent, rejoin group to see the messages");
        Thread.sleep(2000);
        closeEverything(true);
        return rsAppScreen.CHOOSE_GROUP;
      }

      System.out.println("\n\n\nMessages (type '~back' to go back at any time!): ");
      int result = printHistory(noMessages, groupInput);

      // re-encryption necessary if result is 1
      if (result == 1) {
        System.out.println("\nKey change detected. Re-encryption necessary to view messages.");
        System.out.println(
            "Type 'yes' to return to auth server where re-encryption can be requested during login, any other response will return to group selection.");
        String response = scanner.nextLine();

        closeEverything(true);
        if (response.toLowerCase().compareTo("yes") == 0)
          return rsAppScreen.EXIT;
        else
          return rsAppScreen.CHOOSE_GROUP;
      }

      // Thread that prints received messages in real-time
      Thread receiveThread;
        receiveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // For end of history message from RS
                    GroupMessage rsMessage = decrypt((String) groupInput.readObject(), false, true, ++serverToClientGroupCounter);
                    System.out.println(rsMessage.getMessageStr());
                    
                    // If thread is interrupted, it will stop running
                    while (!Thread.currentThread().isInterrupted()) {
                        Thread.sleep(1000);
                        GroupMessage incomingMessage = decrypt((String) groupInput.readObject(), true, true, ++serverToClientGroupCounter);
                        System.out.println(incomingMessage.getSender() + ": " + new String(incomingMessage.getMessage()));
                    }
                } catch (InterruptedException e) {
                    System.err.println("Exiting group...");
                } catch (SocketException e) {
                    System.err.println("Socket closing! Exiting group...");
                } catch(EOFException e) {
                    System.err.println("Error! Connection to socket lost; likely a re-encryption request...\nPlease re-authenticate to obtain the new file key, and enter a confirmation message to exit...");
                } catch (Exception e) {
                    //e.printStackTrace();
                    System.out.println("Error! Please enter a confirmation message to exit...");
                }
            }
        });

      receiveThread.start();
      while (true) {
        try {
          String newMessage = scanner.nextLine();

          if (newMessage.equals("~back")) {
            groupOutput.writeObject(encrypt(newMessage, true, ++clientToServerGroupCounter));
            groupOutput.flush();
            receiveThread.interrupt(); // Interrupts thread, signaling it to stop
            break;
          }

          groupOutput.writeObject(encrypt(newMessage, false, ++clientToServerGroupCounter));
          groupOutput.flush();

          if (!windows) {
            System.out.print("\033[1A"); // Move cursor up one line
            System.out.print("\033[2K"); // Clear line
          }
        } catch (Exception e) {
          receiveThread.interrupt(); // Interrupts thread, signaling it to stop
          break;
        }
      }

    } catch (SocketException e) {
      System.err.println("\nDisconnecting...");
      return rsAppScreen.CHOOSE_GROUP;
    } catch (Exception e) {
      //e.printStackTrace();
      System.err.println("\nError communicating! Please reconnect and try again!");
      return rsAppScreen.CHOOSE_GROUP;
    } finally {
      closeEverything(true); // Since we go back to CHOOSE_GROUP in all cases, need to close group-related socket stuff
    }
    return rsAppScreen.CHOOSE_GROUP;
  }

  // returns a list of RSMessages (serialized and coverted to String) with the messages re-encrypted (and encrypted
  // with session key)
  private List<String> reEncrypt(int noMsg, ObjectInputStream input) {
    List<String> result = new ArrayList<>();
    try {
      // decrypt with session key only
      GroupMessage gMessage = decrypt((String) input.readObject(), false, true, ++serverToClientGroupCounter);
      int oldKeyVersion = gMessage.getKeyVersion();
      int curKeyVersion = Integer.parseInt(new String(user.secretKeys.get(group_id)[1]));
      int keyListIndex = -1;
        
      if (curKeyVersion > 50) {
        // if the old key is too many versions behind the current key, 
        // it will not be in list
        if (curKeyVersion - oldKeyVersion > 49)
          return null;
        else
          keyListIndex = (oldKeyVersion - (curKeyVersion - 50) - 1);
      } 
      else 
        keyListIndex = oldKeyVersion - 1;

      // then decrypt with old file key
      byte[] oldKeyBytes = user.groupKeys.get(keyListIndex);
      SecretKey oldKey = new SecretKeySpec(oldKeyBytes, "AES");
      Cipher fileCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
      fileCipher.init(Cipher.DECRYPT_MODE, oldKey, new IvParameterSpec(gMessage.getIV()));
      gMessage.setMessage(fileCipher.doFinal(gMessage.getMessage()));
      String messageStr = new String(gMessage.getMessage(), StandardCharsets.UTF_8);
      // re-encrypt with current file key
      result.add(encrypt(messageStr, false, ++clientToServerGroupCounter));

      for (int i = 1; i < noMsg; i++){
          // repeat for remaining messages
          gMessage = decrypt((String) input.readObject(), false, true, ++serverToClientGroupCounter);
          fileCipher.init(Cipher.DECRYPT_MODE, oldKey, new IvParameterSpec(gMessage.getIV()));    // To change IV
          gMessage.setMessage(fileCipher.doFinal(gMessage.getMessage()));
          messageStr = new String(gMessage.getMessage(), StandardCharsets.UTF_8);
          result.add(encrypt(messageStr, false, ++clientToServerGroupCounter));
        }
      }
      catch (Exception e) {
        return null;
      }
    
    return result;
  }

  // return 0 if successful, 1 if re-encryption necessary
  private int printHistory(int noMsg, ObjectInputStream input) {
    String serializedMessage = null;
    GroupMessage gMessage = null;
    for (int i = 0; i < noMsg; i++) {
      try {
        gMessage = decrypt((String) input.readObject(), true, true, -1);  // GroupMessages of the past have unknown counters, so don't check (grpMsg = true)

        // EndToEndEncrypted is also checked just on off chance an adversary names
        // themself ERROR! and sends ERROR!
        if (gMessage.getMessageStr().equals("ERROR!") && gMessage.getSender().equals("ERROR!")
            && !gMessage.getEndToEndEncrypted()) {
          // if this specifically is returned, file key decryption failed
          // this means that wrong key was used to decrypt, meaning key was updated
          return 1;
        }
      } catch (Exception e) {
        //e.printStackTrace();
      }
      System.out.println(gMessage.getSender() + ": " + new String(gMessage.getMessage()));
    }
    return 0;
  }

  // If group=true, then close group socket stuff. Else, close rs socket stuff
  private void closeEverything(boolean group) {
    try {
      if (group) {
        groupInput.close();
        groupOutput.close();
        groupSocket.close();
      } else {
        rsInput.close();
        rsOutput.close();
        rsSocket.close();
      }
    } catch (Exception e) {
    }
  }

  // 0 = success, 1 = no pk, 2 = signature fail, 3 = wrong message from server, 4
  // = invalid timestamp, 5 = exception
  @SuppressWarnings("unchecked")
  private int verificationProtocol() {
    try {
      // get RS' public key (and check that the key exists)
      RSAPublicKey pubKey = App.publicKeys.get(App.ip);
      if (pubKey == null)
        return 1;

      // generate nonce r1
      r = new SecureRandom();
      byte[] r1 = new byte[32];
      r.nextBytes(r1);

      // send encrypted r1 (with pubKey) to RS
      Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
      rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
      rsOutput.writeObject(rsaCipher.doFinal(r1));
      rsOutput.flush();

      // Get r2 and signature from the RS (sent as a byte[2][])
      byte[][] r2Pair = (byte[][]) rsInput.readObject();
      byte[] r2 = r2Pair[0];
      byte[] signature = r2Pair[1];

      // verify signature
      Signature verifier = Signature.getInstance("RSASSA-PSS", "BC");
      verifier.initVerify(pubKey);
      verifier.update(r2);
      if (!verifier.verify(signature))
        return 2;

      // Create session key with r1 xor r2 as the seed
      byte[] seed = new byte[32];
      for (int i = 0; i < 32; i++)
        seed[i] = (byte) (r1[i] ^ r2[i]);

      sessionKey = deriveAESKey(seed);
      hmacKey = deriveHMacKey(seed);
      hmac.init(new KeyParameter(hmacKey.getEncoded()));

      // decrypt message from RS using sessionKey
      String encryptedMessage;
      try {
        byte[][] resp = (byte[][]) rsInput.readObject();
        Cipher sessionCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(resp[1]));
        encryptedMessage = new String(sessionCipher.doFinal(resp[0]), StandardCharsets.UTF_8);
      } catch (Exception e) {
        return 3;
      }

      // Verify that decrypted message is correct
      if (!encryptedMessage.equals("Session Key Established"))
        return 3;

      // encrypt token using sessionKey and send to RS
      try {
        byte[] message = TokenSerializer.serializeToken(user.token).getBytes();
        Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
        byte[] iv = new byte[aesCipher.getBlockSize()];
        r.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
        byte[] encrypted = aesCipher.doFinal(message);

        rsOutput.writeObject(new byte[][] { encrypted, iv, user.signature });
        rsOutput.flush();
      } catch (Exception e) {
        return 4;
      }

      GroupMessage rsResponse;

      try {
        // This decryption actually uses the regular decrypt function (with RSMessages /
        // GroupMessages)
        rsResponse = decrypt((String) rsInput.readObject(), false, false, ++serverToClientCounter);

        if (rsResponse == null)
          return 4;
      } catch (ClassCastException e) {
        ////e.printStackTrace();
        return 4;
      }

      long time = Long.parseLong(rsResponse.getMessageStr());
      Timestamp serverTs = new Timestamp(time);

      // If timestamp received (server timestamp) > timestamp from token (user
      // timestamp) + 6, return 4. Else continue with protocol
      Timestamp userTsPlusSix = new Timestamp(user.token.getTimestamp().getTime() + 360000); // 360000 = 6 minutes in
                                                                                             // Millis
      if (serverTs.after(userTsPlusSix))
        return 4;

      return 0; // Return 0, signifying successful authentication
    } catch (Exception e) {
      // //e.printStackTrace();
      closeEverything(false);
      return 5;
    }
  }

  /**
   * AES Encryption
   * 
   * @param input,     the String the user sent to encrypt
   * @param forServer, true if the message is for the server (AKA don't encrypt
   *                   with file key), false otherwise
   * @param counter,   server or group counter, depending on if group chat message or not
   * @return byte[] representing the serialized RSMessage object (with the
   *         encrypted GroupMessage inside)
   */
  private String encrypt(String message, boolean forServer, int counter)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    try {
      Cipher aesCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
      byte[] ivSession = new byte[aesCipher.getBlockSize()];
      r.nextBytes(ivSession);
      IvParameterSpec ivSpec;

      // If forServer is false, encrypt with file key (and set endToEndEncrypted in
      // GroupMessage to true). Else, skip that step (and keep endToEndEncrypted false)
      // Also, change the -1 to the key version if end to end encrypted (keep -1 if not end to end encrypted)

      // If not for server, first encrypt with file key
      byte[] firstEncrypted = message.getBytes();
      byte[] hmacResult = null;
      byte[] ivFile = null;
      if(!forServer)
      {
        // Encrypt with file key
        SecretKey fileKey = new SecretKeySpec(user.secretKeys.get(group_id)[0], "AES");

        // Initialize ivFile / ivSpec for 2nd encryption
        ivFile = new byte[aesCipher.getBlockSize()];
        r.nextBytes(ivFile);
        ivSpec = new IvParameterSpec(ivFile);
        aesCipher.init(Cipher.ENCRYPT_MODE, fileKey, ivSpec);

        firstEncrypted = aesCipher.doFinal(firstEncrypted);

        // Create HMAC
        hmac.update(firstEncrypted, 0, firstEncrypted.length);
        hmacResult = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacResult, 0);
      }

      int ver = forServer ? -1 : Integer.parseInt(new String(user.secretKeys.get(group_id)[1]));
      GroupMessage msg = new GroupMessage(firstEncrypted, ivFile, hmacResult, user.name, ver,
          counter, !forServer);

      // Encrypt with session key
      ivSpec = new IvParameterSpec(ivSession);
      aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);
      byte[] secondEncrypted = aesCipher.doFinal(GroupMessage.serializeMessage(msg).getBytes());

      // Create HMAC
      hmac.update(secondEncrypted, 0, secondEncrypted.length);
      byte[] hmacResult2 = new byte[hmac.getMacSize()];
      hmac.doFinal(hmacResult2, 0);

      // Store in RSMessages object and return
      RSMessages RSMsg = new RSMessages(secondEncrypted, ivSession, user.name, hmacResult2);
      return RSMessages.serializeMessage(RSMsg);
    } catch (Exception e) {
      //e.printStackTrace();
      return null;
    }
  }

  /**
   * AES Decryption
   * 
   * @param input,      the byte[] array sent by the server to decrypt
   * @param useFileKey, true if we should use the file key to decrypt the message
   *                    (i.e., if it's from another user). False otherwise
   * @param grpMsg,     if this is a message in the group, don't check the counter (unnecessary)
   * @param counter,    server or group counter, depending on if group chat message or not
   * @return GroupMessage object (decrypted) consisting of message (decrypted if
   *         necessary)
   * 
   *         Note: This will return null on a normal error, and a specific error
   *         GroupMessage object if the error happens during the file key
   *         decryption
   */
  private GroupMessage decrypt(String input, boolean useFileKey, boolean grpMsg, int counter)
      throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
    try {
      RSMessages RSMsg = RSMessages.deserializeMessage(input);

      // Verify RSMsg HMAC before continuing. Throw exception if fails
      hmac.update(RSMsg.getMessage(), 0, RSMsg.getMessage().length);
      byte[] hmacResult = new byte[hmac.getMacSize()];
      hmac.doFinal(hmacResult, 0);
      if (!Arrays.equals(hmacResult, RSMsg.getHMAC()))
        throw new InvalidHMACException();

      // first decrypt with session key
      Cipher sessionCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
      sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(RSMsg.getIV()));
      byte[] sessionDecrypted = sessionCipher.doFinal(RSMsg.getMessage());

      GroupMessage groupMsg = GroupMessage.deserializeMessage(new String(sessionDecrypted));
      try {
        // then decrypt with file key if necessary
        if (useFileKey) {
          if (Integer.parseInt(new String(user.secretKeys.get(group_id)[1])) != groupMsg.getKeyVersion())
            return new GroupMessage("ERROR!".getBytes(), null, null, "ERROR!", -1, -1, false);
          Cipher fileCipher = Cipher.getInstance("AES/CFB/NoPadding", "BC");
          SecretKey fileKey = new SecretKeySpec(user.secretKeys.get(group_id)[0], "AES");
          fileCipher.init(Cipher.DECRYPT_MODE, fileKey, new IvParameterSpec(groupMsg.getIV()));
          groupMsg.setMessage(fileCipher.doFinal(groupMsg.getMessage()));
        }
      } catch (Exception e) {   // TODO: Maybe figure out what exception this throws and specify it in particular
        return new GroupMessage("ERROR!".getBytes(), null, null, "ERROR!", -1, -1, false);
      }

      // If counter doesn't match, throw error. If grpMsg, then it is a GroupMessage History (thus, don't check counter)
      if(!grpMsg && groupMsg.getCounter() != counter)
        throw new InvalidHMACException();
      
      return groupMsg;
    } catch (InvalidHMACException e) {
      ////e.printStackTrace();
      System.out.println("Error! HMAC or counter doesn't match!");
      return null; 
    }catch (Exception e) {
      // //e.printStackTrace();
      return null;
    }
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

  // TODO: decryption for group messages with file key and reencryption process
}