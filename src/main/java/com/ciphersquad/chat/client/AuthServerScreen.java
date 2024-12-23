package com.ciphersquad.chat.client;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.InputMismatchException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.json.JSONArray;
import org.json.JSONObject;

import com.ciphersquad.chat.App;
import com.ciphersquad.chat.AuthenticationServer.ASKeypairGen;
import com.ciphersquad.chat.AuthenticationServer.AuthIntegrityMessage;
import com.ciphersquad.chat.AuthenticationServer.AuthRequest;
import com.ciphersquad.chat.AuthenticationServer.AuthResponse;
import com.ciphersquad.chat.AuthenticationServer.TokenSerializer;
import com.ciphersquad.chat.ResourceServer.RSKeyStorage;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import static com.ciphersquad.chat.AuthServer.generateKeyPair;
import static com.ciphersquad.chat.AuthServer.generateSharedSecret;
import static com.ciphersquad.chat.AuthServer.encrypt;
import static com.ciphersquad.chat.AuthServer.decrypt;
import static com.ciphersquad.chat.AuthServer.deriveIntegrityKey;
import static com.ciphersquad.chat.AuthServer.deriveEncryptKey;;


public class AuthServerScreen {
    private static String host = "localhost";
    public static HashMap<String, byte[]> publicKeys = new HashMap<String, byte[]>();

    private static void getUserPass(User user, Scanner scanner) {

        System.out.println("\nPlease enter username");
        user.name = scanner.nextLine();

        System.out.println("Please enter password");
        user.password = scanner.nextLine();
    }

    public static Screen loginScreen(User user, Scanner scanner, AuthServerClient as) {
        int server2ClientCounter = 1;
        int client2ServerCounter = 1;
        Mac hmac;
        Cipher encryptCipher;
        Cipher decryptCipher;
        // First, choose Auth server IP/Port

        System.out.println("\nAS Screen: Auth Server IP/Port Selection");
        System.out.println("Choose an option:");
        System.out.println("1. Update Auth Server IP and Port");
        System.out.println("2. Continue to connect to server");
        int choice;
        try {
            choice = scanner.nextInt();

        } catch (Exception e) {
            scanner.nextLine(); // Consume the newline character
            System.err.println("Invalid input");
            return Screen.LOGIN;
        }
        scanner.nextLine(); // Consume the newline character
        switch(choice) {
            case 1: // Change Auth Server IP
                System.out.println("What auth server host would you like to connect to? (localhost is default)");
                host = scanner.nextLine();
                System.out.println("What auth server port would you like to connect to?");
                try {
                    as.setPort(scanner.nextInt());
                } catch (Exception e) {
                    scanner.nextLine(); // Consume the newline character
                    System.err.println("Invalid input");
                    return Screen.LOGIN;
                }
                break;
            case 2:
                break;
            default:
                System.out.println("Invalid Input");
                return Screen.LOGIN;
        }


        try {

            // Next, connect to server
            System.out.println("Connecting to server....");
            final Socket sock = new Socket(host, as.getPort()); 
            final ObjectOutputStream output = new ObjectOutputStream(sock.getOutputStream());
            final ObjectInputStream input = new ObjectInputStream(sock.getInputStream());
            System.out.println("Connected to server!");

            // Next, get crypto key via DH
            KeyPair clientKeyPair = generateKeyPair();
            PublicKey clientPublicKey = clientKeyPair.getPublic();
            AuthRequest keyAuthRequest = new AuthRequest(clientPublicKey, AuthRequest.AuthType.DH_KEY_EXCHANGE);
            output.writeObject(keyAuthRequest);
            output.flush(); // Ensure the request is sent

            // Wait for AS to send their public key
            AuthResponse dhAuthResponse = (AuthResponse) input.readObject();
            PublicKey serverPublicKey = dhAuthResponse.getPublicKey();
            byte[] serverSignature = dhAuthResponse.getSignature();

            // Verify the signature
            PublicKey ASPubKey = ASKeypairGen.loadPublicKey();
            Signature signer = Signature.getInstance("SHA256withRSA/PSS", "BC");
            signer.initVerify(ASPubKey);
            signer.update(serverPublicKey.getEncoded());
            if (!signer.verify(serverSignature)) {
                System.out.println("Signature verification failed");
                sock.close();
                return Screen.LOGIN;
            }

            // Get shared key
            byte[] sharedSecret = generateSharedSecret(clientKeyPair.getPrivate(), serverPublicKey);
            SecretKeySpec aesKey = deriveEncryptKey(sharedSecret);
            SecretKeySpec hmacKey = deriveIntegrityKey(sharedSecret);

            //System.out.println("AES Key: "+ aesKey.toString());

            // Recieve IV
            dhAuthResponse = (AuthResponse) input.readObject();
            byte[] iv = dhAuthResponse.getIV();

            encryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            decryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            ivSpec = new IvParameterSpec(iv);
            decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            hmac = new HMac(new SHA256Digest());
            hmac.init(new  KeyParameter(hmacKey.getEncoded()));
            //System.out.println("IV: " + iv.toString());

            // Next sign in (sign in or make acct)
            boolean integrityFailed = false;
            boolean signedIn = false;
            while(!signedIn && !integrityFailed) {
                System.out.println("\nAS Screen: Login");
                System.out.println("Choose an option:");
                System.out.println("1. Login");
                System.out.println("2. Register account");
                try {
                    choice = scanner.nextInt();
                    scanner.nextLine(); // Consume the newline character

                } catch (Exception e) {
                    scanner.nextLine(); // Consume the newline character
                    System.err.println("Invalid input");
                    sock.close();
                    return Screen.LOGIN;
                }
                if (choice == 1) { // Log in
                    getUserPass(user, scanner);
                    
                    // create and send auth request over socket
                    AuthRequest authRequest = new AuthRequest(user.name, user.password, AuthRequest.AuthType.LOGIN);
                    sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);
                    System.out.println("Auth request sent for user: " + user.name);

                    AuthResponse authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                    if (authResponse == null) {
                        System.out.println("Integrity check failed. Exiting...");
                        integrityFailed = true;
                    } else if (authResponse.isSuccessful()) {
                        System.out.println("Sign in successful!");
                        signedIn = true; //Break out of loop
                    } else {
                        System.out.println("Authentication failed for user: " + user.name);
                    }
                } else if (choice == 2) { //Make a new account (and dont log in)
                    getUserPass(user, scanner);

                    // create and send auth request over socket
                    AuthRequest authRequest = new AuthRequest(user.name, user.password, AuthRequest.AuthType.REGISTER);
                    sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);

                    System.out.println("Auth request sent for user: " + user.name);
                    AuthResponse authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                    if (authResponse == null) {
                        System.out.println("Integrity check failed. Exiting...");
                        integrityFailed = true;
                    } else if (authResponse.isSuccessful()) {
                        System.out.println("Registration successful!");
                    } else {
                        System.out.println("Registration failed for user: " + user.name);
                    }
                }
            }

            // Now, they should be signed in.
            while (!integrityFailed) {
                System.out.println("\nAS Screen");
                System.out.println("Choose an option:");
                System.out.println("1. Get Token and sign into RS");
                System.out.println("2. Make Group Chat");
                System.out.println("3. Delete Person from Group Chat (Admin only)");
                System.out.println("4. Add Person to Group Chat (Admin only)");
                System.out.println("5. Delete account");
                System.out.println("6. List Groups");
                System.out.println("7. Delete Group Chat (Admin only)");
                System.out.println("8. Leave AS");

                try {
                    choice = scanner.nextInt();
                } catch (Exception e) {
                    scanner.nextLine(); // Consume the newline character
                    System.err.println("Invalid input");
                    sock.close();
                    return Screen.LOGIN;
                }
                scanner.nextLine(); // Consume the newline character

                int groupChatNumber = -1;

                switch (choice) {
                    default:
                        System.out.println("Invalid Choice.");
                        break;
                    case 1: //Get Token
                        //read public keys
                        boolean res = readPublicKeys();
                        if (!res){
                            break;
                        }
                        //TODO: PROMPT USER AND GET HASH OF RS PUBLIC KEY, IF SERVER DOESNT EXIST THROW AN ERROR
                        System.out.println("Enter the IP of the Resource Server you would like to join: ");
                        App.ip = scanner.nextLine();

                        byte[] hashedPubKey = publicKeys.get(App.ip);
                        if (hashedPubKey == null){
                            System.out.println("Server does not Exist! ");
                            break;
                        }
                        
                        AuthRequest authRequest = new AuthRequest(hashedPubKey, AuthRequest.AuthType.GET_TOKEN);

                        //user.token.setRsPk(hashedPubKey);
                        //System.out.println("Hashed PK: " + hashedPubKey);

                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);

                        System.out.println("Auth request sent for user: " + user.name);

                        AuthResponse authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("Token retrieval successful!");
                            // System.out.println("Authentication successful! Token: " + authResponse.getToken());
                            user.token = TokenSerializer.deserializeToken(authResponse.getToken());
                            user.signature = authResponse.getSignature();
                            user.secretKeys = authResponse.getSecretKeys();

                            // byte[] sig = authResponse.getSignature();
                            
                            // PublicKey pubKey = ASKeypairGen.loadPublicKey();
        
                            // Signature signer = Signature.getInstance("SHA256withRSA/PSS", "BC");
                            // signer.initVerify(pubKey);
                            // byte[] tokenBytes = authResponse.getToken().getBytes();
                            
                            // signer.update(tokenBytes);
                            // boolean success = signer.verify(sig);

                            // if (success){
                            //     System.out.println("Verified Signature!");
                            // }else{
                            //     System.out.println("WRONG SIGNATURE!");
                            // }

                            // retrievel of keys for re-encryption
                            System.out.println("Are you currently attempting to start a re-encryption process for a group? Type 'yes' to do so");
                            String response = scanner.nextLine();

                            if (response.compareTo("yes") == 0){
                                System.out.println("What is the name of the group needing re-encryption?");
                                String name = scanner.nextLine();
                                AuthRequest keysRequest = new AuthRequest(user.token, user.signature, AuthRequest.AuthType.GET_GROUP_KEYS, name);
                                sendEncrypted(keysRequest, hmac, client2ServerCounter++, encryptCipher, output);
                                AuthResponse keysResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                                if(keysResponse == null || !keysResponse.isSuccessful()) {
                                    System.out.println("Re-encryption request failed. Logging into RS");
                                    user.groupKeys = null;
                                    user.reencryptionGroup = -1;
                                    user.needsReencryption = false;
                                } else {
                                    System.out.println("Re-encryption request successful. Logging into RS — upon entering the RS, please attempt to join group " + name + ", and the re-encryption process will then begin.");
                                    user.groupKeys = keysResponse.getAllGroupKeys();
                                    user.reencryptionGroup = keysResponse.getGroupID();
                                    user.needsReencryption = true;
                                }
                            } else {
                                user.groupKeys = null;
                                user.reencryptionGroup = -1;
                                user.needsReencryption = false;
                            }
                            
                            sock.close();
                            return Screen.RESOURCE;
                        } else {
                            System.out.println("Token retrieval failed for user: " + user.name);
                            break;
                        }
                    case 2: // Make Groupchat
                        ArrayList<String> people = new ArrayList<String>();
                        System.out.println("Enter the group chat number (must be positive and between 0-9999):");

                        // Loop to receive valid group number input
                        while(groupChatNumber < 0) {
                            try {
                                groupChatNumber = scanner.nextInt();
                                scanner.nextLine();     // Consume newline character

                                if (groupChatNumber < 0)
                                    throw new NumberFormatException();
                            } catch(Exception e) {
                                System.out.println("Error! Please enter a valid (positive) integer!");

                                // Read line if error caused by scanner
                                if(e instanceof InputMismatchException)
                                    scanner.nextLine();
                            }
                        }

                        boolean finishedEntering = false;
                        while (!finishedEntering) {
                            System.out.println(
                                    "EXCLUDING YOURSELF. Enter the name of the person you would like to add to the group chat (type 'done' when finished):");
                            String person = scanner.nextLine();
                            if (person.equals("done")) {
                                finishedEntering = true;
                            } else {
                                people.add(person);
                            }
                        }
                        
                        //check to see if any members were added first...
                        if (people == null || people.isEmpty()) {
                            System.out.println("Error: You didnt add any members to the group chat!");
                            break;
                        } else {
                            //System.out.println("Members being sent: " + people);
                            authRequest = new AuthRequest(null, null, AuthRequest.AuthType.MAKE_GROUP, people, String.valueOf(groupChatNumber));
                            sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);
                        }

                        System.out.println("Auth request sent for user: " + user.name);

                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("Group chat created successfully!");
                            break;
                        } else {
                            System.out.println(authResponse.getMessage());
                            break;
                        }
                    case 3: //Delete person from GC                  
                    System.out.println("Delete Person from Group Chat:");
                        System.out.println("Enter the group chat number:");

                        // Loop to receive valid group number input
                        while(groupChatNumber < 0) {
                            try {
                                groupChatNumber = scanner.nextInt();
                                scanner.nextLine();     // Consume newline character

                                if (groupChatNumber < 0)
                                    throw new NumberFormatException();
                            } catch(Exception e) {
                                System.out.println("Error! Please enter a valid (positive) integer!");
                                
                                // Read line if error caused by scanner
                                if(e instanceof InputMismatchException)
                                    scanner.nextLine();
                            }
                        }

                        System.out.println("Enter the name of the person you would like to delete from the group chat:");
                        String person = scanner.nextLine();

                        people = new ArrayList<String>();
                        people.add(person);

                        authRequest = new AuthRequest(null, null, AuthRequest.AuthType.REMOVE_USER_FROM_GROUP, people, String.valueOf(groupChatNumber));

                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);
                        System.out.println("Auth request sent for user: " + user.name);

                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("Person deleted from group chat successfully!");
                            break;
                        } else {
                            System.out.println(authResponse.getMessage());
                            break;
                        }
                    case 4: //Add Person to Group Chat
                        //System.out.println("Add Person to Group Chat:");
                        System.out.println("Enter the group chat number that you would like to add a user to:");
                        
                        // Loop to receive valid group number input
                        while(groupChatNumber < 0) {
                            try {
                                groupChatNumber = scanner.nextInt();
                                scanner.nextLine();     // Consume newline character

                                if (groupChatNumber < 0)
                                    throw new NumberFormatException();
                            } catch(Exception e) {
                                System.out.println("Error! Please enter a valid (positive) integer!");
                                
                                // Read line if error caused by scanner
                                if(e instanceof InputMismatchException)
                                    scanner.nextLine();
                            }
                        }
                        
                        System.out.println("Enter the name of the person you would like to add to the group chat:");
                        person = scanner.nextLine();
                        people = new ArrayList<String>();
                        people.add(person);

                        //send request to server
                        authRequest = new AuthRequest(null, null, AuthRequest.AuthType.ADD_USER_TO_GROUP, people, String.valueOf(groupChatNumber));
                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);

                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("User added to group chat successfully!");
                            break;
                        } else {
                            System.out.println(authResponse.getMessage());
                            break;
                        }
                    case 5: //Delete account
                        // Make sure they want to do it
                        System.out.println("Type yes to confirm");
                        String confirmation = scanner.nextLine();
                        if (!confirmation.equalsIgnoreCase("yes")) {
                            System.out.println("Account deletion cancelled.");
                            break;
                        }

                        // create and send auth request over socket
                        authRequest = new AuthRequest(null, null, AuthRequest.AuthType.DELETE);
                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);
                        System.out.println("Auth request sent for user: " + user.name);

                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("Account deletion successful!");
                            sock.close();
                            return Screen.LOGIN;
                        } else {
                            System.out.println("Account deletion failed for user: " + user.name);
                            break;
                        }
                    case 6: //List Groups
                        authRequest = new AuthRequest(null, null, AuthRequest.AuthType.LIST_GROUP);
                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);

                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        }
                        System.out.println(authResponse.getMessage());
                        
                        break;
                    case 7: // Delete Group Chat
                        System.out.println("Remove Group Chat:");
                        System.out.println("Enter the group chat number to remove:");
                    
                        // Loop to receive valid group number input
                        while (groupChatNumber < 0) {
                            try {
                                groupChatNumber = scanner.nextInt();
                                scanner.nextLine(); // Consume newline character
                    
                                if (groupChatNumber < 0)
                                    throw new NumberFormatException();
                            } catch (Exception e) {
                                System.out.println("Error! Please enter a valid (positive) integer!");
                    
                                // Read line if error caused by scanner
                                if (e instanceof InputMismatchException)
                                    scanner.nextLine();
                            }
                        }
                                    
                        // Create and send the auth request to remove the group
                        authRequest = new AuthRequest(null, null, AuthRequest.AuthType.REMOVE_GROUP, null, String.valueOf(groupChatNumber));
                        sendEncrypted(authRequest, hmac, client2ServerCounter++, encryptCipher, output);
                        System.out.println("Auth request sent for user: " + user.name);
                    
                        // Read the server's response
                        authResponse = recieveEncrypted(hmac, server2ClientCounter++, decryptCipher, input);
                        if (authResponse == null) {
                            System.out.println("Integrity check failed. Exiting...");
                            integrityFailed = true;
                        } else if (authResponse.isSuccessful()) {
                            System.out.println("Group chat removed successfully!");
                            break;
                        } else {
                            System.out.println(authResponse.getMessage());
                            break;
                        } 
                    case 8: // Leave AS
                        sock.close();
                        return Screen.LOGIN;
                }
            }
            // If integrity failed, return to login screen
            sock.close();
            return Screen.LOGIN;

        } catch (Exception e) {
            System.err.println("Error, Authentication Server Disconnected: " + e);
            //e.printStackTrace();
            return Screen.LOGIN;
        }
    }

    private static void sendEncrypted(AuthRequest authRequest, Mac hmac, int client2ServerCounter, Cipher encryptCipher, ObjectOutputStream output) throws Exception { 
        authRequest.setClient2ServerCounter(client2ServerCounter);
        byte[] ciphertext = encrypt(authRequest.toString(), encryptCipher);
        AuthIntegrityMessage authIntegrityMessage = new AuthIntegrityMessage(ciphertext, hmac);
        output.writeObject(authIntegrityMessage);
        output.flush(); // Ensure the request is sent
    }

    private static AuthResponse recieveEncrypted(Mac hmac , int server2ClientCounter, Cipher decryptCipher, ObjectInputStream input) throws Exception {
        AuthIntegrityMessage authIntegrityMessage = (AuthIntegrityMessage) input.readObject();
        if (!authIntegrityMessage.verifyHmac(hmac)) {
            System.out.println("HMAC verification failed");
            return null; // Integrity check failed
        }
        byte[] ciphertext = authIntegrityMessage.getCiphertext();
        String decryptedString = (String) decrypt(ciphertext, decryptCipher);
        AuthResponse authResponse = AuthResponse.fromString(decryptedString);
        if (authResponse.getServer2ClientCounter() != server2ClientCounter) {
            System.out.println("Server to client counter mismatch");
            return null;
        }
        return authResponse;
    }

    private static boolean readPublicKeys() {
        String filePath = "./src/main/java/com/ciphersquad/chat/ResourceServer/RSKeys/rs_public_key.json";
        File file = new File(filePath);
    
        if (!file.exists()) {
            System.out.println("file: " + file + " does not exist!");
        }else{
    
            // Read JSON from file, convert to PK and store in HashMap ("<IP>" -> PK)
            try (FileReader r = new FileReader(filePath);) {
                Gson gson = new Gson();

                // Extract keys.json as JsonArray
                JsonArray arr = gson.fromJson(r, JsonArray.class);

                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                // For each (IP, key) pair in keys.json, store the byte array in the mapping
                for (int i = 0; i < arr.size(); i++) {
                    JsonObject obj = arr.get(i).getAsJsonObject();

                    // Extract encoded key as RSKeyStorage object (which is just an object with IP
                    // and byte array variables)
                    RSKeyStorage encodedPk = gson.fromJson(obj, RSKeyStorage.class);

                    //storing the public keys as hashed byte arrays
                    byte[] rawKey = encodedPk.getKey();
                    byte[] hashedKey = digest.digest(rawKey);

                    // Store the hashed byte array in the mapping
                    publicKeys.put(obj.get("server").getAsString(), hashedKey);
                }

                return true;
            } catch (Exception e) {
                //e.printStackTrace();
                System.err.println("Error reading public keys from file!");
                return false;
            }
        }
        return false;
    }
}