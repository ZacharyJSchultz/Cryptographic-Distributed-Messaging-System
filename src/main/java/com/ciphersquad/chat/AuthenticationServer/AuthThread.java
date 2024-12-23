package com.ciphersquad.chat.AuthenticationServer;

import java.lang.Thread;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.LongFunction;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import com.ciphersquad.chat.AuthServer;
import com.ciphersquad.chat.client.*;
import static com.ciphersquad.chat.AuthServer.generateKeyPair;
import static com.ciphersquad.chat.AuthServer.generateSharedSecret;
import static com.ciphersquad.chat.AuthServer.deriveEncryptKey;
import static com.ciphersquad.chat.AuthServer.deriveIntegrityKey;
import static com.ciphersquad.chat.AuthServer.encrypt;
import static com.ciphersquad.chat.AuthServer.decrypt;

public class AuthThread extends Thread {
    static {
        Security.addProvider(new BouncyCastleProvider()); 
    }
    private final Socket socket;
    private ObjectOutputStream output;
    private ObjectInputStream input;

    // socket passed from server
    public AuthThread(Socket _socket) {
        this.socket = _socket;
    }

    // This method reads username prompts and authenticates if applicable
    public void run() {
        int client2ServerCounter = 1;
        int server2ClientCounter = 1;
        try {
            HMac hmac;
            System.out.println("New connection from " + socket.getInetAddress() + ":" + socket.getPort());

            // I/O from socket
            output = new ObjectOutputStream(socket.getOutputStream());
            input = new ObjectInputStream(socket.getInputStream());

            // user for whole session
            User user = new User();

            // Diffie hellman
            //System.out.println("Starting Diffie Hellman Secret Exchange");
            KeyPair serverKeyPair = generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            Cipher encryptCipher, decryptCipher;

            // Get client public key
            AuthRequest dhAuthRequest;
            dhAuthRequest = (AuthRequest) input.readObject();
            PublicKey clientPublicKey = dhAuthRequest.getPublicKey();

            // Send server public key
            byte[] clientSignature = signBytes(serverPublicKey.getEncoded());
            AuthResponse dhAuthResponse = new AuthResponse(serverPublicKey, clientSignature);
            output.writeObject(dhAuthResponse);
            output.flush();

            // Get shared key
            byte[] sharedSecret = generateSharedSecret(serverKeyPair.getPrivate(), clientPublicKey);

            SecretKeySpec aesKey = deriveEncryptKey(sharedSecret);
            SecretKeySpec hmacKey = deriveIntegrityKey(sharedSecret);

            //System.out.println("AES Key: "+ aesKey.toString());

            // Generate and send IV
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            dhAuthResponse = new AuthResponse(iv);
            output.writeObject(dhAuthResponse);
            output.flush();
            //System.out.println("IV: " + iv.toString());


            encryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

            decryptCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
            ivSpec = new IvParameterSpec(iv);
            decryptCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

            hmac = new HMac(new SHA256Digest());
            hmac.init(new KeyParameter(hmacKey.getEncoded()));

            // Log in
            boolean integrityFailed = false;
            boolean loggedIn = false;
            while (!loggedIn) {
                AuthResponse authResponse;
                AuthRequest inputAuthRequest;
                inputAuthRequest = recieveEncrypted(hmac, client2ServerCounter++, decryptCipher, input);
                if(inputAuthRequest == null) {
                    System.out.println("Integrity check failed");
                    integrityFailed = true;
                    break;
                }
                System.out.println("AuthRequest received with username: " + inputAuthRequest.getUsername());
                user = new User();
                user.name = inputAuthRequest.getUsername();
                user.password = inputAuthRequest.getPassword();

                if(inputAuthRequest.getAuthType() == AuthRequest.AuthType.LOGIN) {
                    if (AuthServer.authenticate(user)) { // Correct credentials
                        authResponse = new AuthResponse(true, "Authenticated", null);
    
                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        
                        loggedIn = true;
    
                    } else { // wrong username or password
                        authResponse = new AuthResponse(false, "Failed authentication", null);
                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                    }
                } else if (inputAuthRequest.getAuthType() ==  AuthRequest.AuthType.REGISTER) {
                    System.out.println("Register request received for user: " + user.name);
                    if (!AuthServer.userExists(user.name)) {
                        boolean isUserAdded = AuthServer.addNewUser(user.name, user.password);
                        if (isUserAdded) {      // successfully added new user
                            ArrayList<String> permissions = new ArrayList<>(); // empty list because user is new
                            user.token = new Token(user.name, permissions);
                            //String token = TokenSerializer.serializeToken(user.token);
                            //Sign the token and send the signed token
                            //String signedToken = signToken(token);
                            //System.out.println("Registered user signed token. " + signedToken);
                            authResponse = new AuthResponse(true, "Account created", null); // sending serialized token
                            
                            // add new user to data base
                            MetadataSerializer.serializeMetadata(user);
                        } else { // username is already being used failed to add
                            authResponse = new AuthResponse(false, "Username already exists.", null);
                        }
                    } else {
                        authResponse = new AuthResponse(false, "Username already exists.", null);
                    }
                    sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                }
            }

            while(!integrityFailed) { //run as long as connected
                AuthRequest inputAuthRequest = recieveEncrypted(hmac, client2ServerCounter++, decryptCipher, input);
                if(inputAuthRequest == null) {
                    System.out.println("Integrity check failed");
                    integrityFailed = true;
                    break;
                }
                AuthResponse authResponse;

                switch (inputAuthRequest.getAuthType()) {
                    case GET_TOKEN:
                        System.out.println("Token request received for user: " + user.name);
                        if (AuthServer.authenticate(user)) {    // Correct credentials
                            // serialize token, then send that string to client
                            ArrayList<String> permissions = AuthServer.getPermissions(user.name);
                            
                            user.token = new Token(user.name, permissions);
                            user.token.setRsPk(inputAuthRequest.getHashedPK());

                            String token = TokenSerializer.serializeToken(user.token);
                            
                            //System.out.println("Hashed PK: " + user.token.getRsPK());
                            //sign token and send 
                            
                            byte[] signature = signToken(token);

                            //System.out.println("User: " + user.name + " Token: " + token + " Signature: " + signature);
                            
                            authResponse = new AuthResponse(true, null, token, AuthServer.getSecretKeyMap(permissions), signature);
                            
                            sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                            
                            // remove the D permission (if applicable) from all users after sending token
                            List<String> permissionsToRemove = new ArrayList<>(); 

                            for (String permission : permissions) {
                                if (permission.endsWith("D")) {
                                    permissionsToRemove.add(permission); // add permission to the list for later removal
                                }
                            }

                            // remove those permissions now
                            for (String permission : permissionsToRemove) {
                                AuthServer.removeDPermissionFromAllUsers(permission);
                            }
                            authResponse = new AuthResponse(true,"Authenticated", null);
                            break;

                        } else { // wrong username or password
                            authResponse = new AuthResponse(false, "Failed authentication", null);
                            sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                            break;
                        }

                    case REGISTER:
                        System.out.println("Register request received for user: " + user.name);
                        if (!AuthServer.userExists(user.name)) {

                            boolean isUserAdded = AuthServer.addNewUser(user.name, user.password);
                            if (isUserAdded) {// successfully added new user
                                ArrayList<String> permissions = new ArrayList<>(); // empty list because user is new
                                user.token = new Token(user.name, permissions);
                                String token = TokenSerializer.serializeToken(user.token);
                                authResponse = new AuthResponse(true, null,token); // sending serialized token
                                // add new user to data base
                                MetadataSerializer.serializeMetadata(user);
                            } else { // username is already being used failed to add
                                authResponse = new AuthResponse(false, "Username already exists.", null);
                            }
                        } else {
                            authResponse = new AuthResponse(false, "Username already exists.", null);
                        }
                        output.writeObject(authResponse);
                        output.flush();
                        break;

                    case DELETE:
                            System.out.println("Delete request received for user: " + user.name);
                            Boolean isDeleted = AuthServer.deleteUser(user);
                            if (isDeleted) {
                                authResponse = new AuthResponse(true, "User deleted successfully.", null);
                                sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                                break;
                            } else {
                                authResponse = new AuthResponse(false, "User info incorrect.", null);
                                sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                                break;
                            }
                    case MAKE_GROUP:
                        ArrayList<String> members = inputAuthRequest.getMembers();

                        System.out.println("Make group request received for user: " + user.name);
                        int groupCreated = AuthServer.makeGroup(user, members, inputAuthRequest.getGroupName());

                        // Success
                        switch (groupCreated) {
                            case 0 -> authResponse = new AuthResponse(true, "Group created successfully.", null);
                            // Fail (invalid credentials)
                            case -1 -> authResponse = new AuthResponse(false, "Group creation failed: Incorrect username or password!", null);
                            // Fail (group number in use)
                            case -2 -> authResponse = new AuthResponse(false, "Group creation failed: Group # in use!", null);
                            // Fail (too large group #)
                            case -3 -> authResponse = new AuthResponse(false,
                                    "Group creation failed: Group # is too large! (must be between 0 and 9999)", null);
                            // Default
                            default -> authResponse = new AuthResponse(false, "Group creation failed!", null);
                        }

                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        break;

                    case ADD_USER_TO_GROUP:
                        System.out.println("Add to group request received from user: " + user.name);
                        // first item in arraylist is group number, rest are members
                        int addedToGroup = AuthServer.addToGroup(user, inputAuthRequest.getMembers(),
                                inputAuthRequest.getGroupName());
                        
                        switch(addedToGroup) {
                            // Success
                            case 0 -> authResponse = new AuthResponse(true, "Successfully added to group.", null);
                            // Fail (invalid credentials)
                            case -1 -> authResponse = new AuthResponse(false, "Adding to group failed: Incorrect username or password!", null);
                            // Fail (nonexistent user)
                            case -2 -> authResponse = new AuthResponse(false, "Adding to group failed: User to add does not exist!", null);
                            // Fail (not admin)
                            case -3 -> authResponse = new AuthResponse(false, "Adding to group failed: User is not admin of the group!", null);
                            // Fail (invalid group)
                            case -4 -> authResponse = new AuthResponse(false, "Adding to group failed: Group does not exist!", null);
                            // Fail (invalid group)
                            case -5 -> authResponse = new AuthResponse(false, "Adding to group failed: User to add is already in this group!", null);
                            // Default
                            default -> authResponse = new AuthResponse(false, "Adding to group failed!", null);
                        }

                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        break;

                    // (0=true, -1=failed auth, -2=nonexistent group, -3=not admin, -4=user nonexistent, -5=user not in group)
                    case REMOVE_USER_FROM_GROUP:
                        System.out.println("Remove from group request received from user: " + user.name);
                        // first item in arraylist is group number, rest are members
                        int removedFromGroup = AuthServer.removeFromGroup(user, inputAuthRequest.getMembers(),
                                inputAuthRequest.getGroupName());
                        
                        switch(removedFromGroup) {
                            // Success
                            case 0 -> authResponse = new AuthResponse(true, "Successfully removed user from the group.", null);
                            // Fail (invalid credentials)
                            case -1 -> authResponse = new AuthResponse(false, "Removing from group failed: Incorrect username or password!", null);
                            // Fail (nonexistent group)
                            case -2 -> authResponse = new AuthResponse(false, "Removing from group failed: Invalid group!", null);
                            // Fail (not admin)
                            case -3 -> authResponse = new AuthResponse(false, "Removing from group failed: User is not admin of the group!", null);
                            // Fail (nonexistent user)
                            case -4 -> authResponse = new AuthResponse(false, "Removing from group failed: User does not exist!", null);
                            // Fail (user not in group)
                            case -5 -> authResponse = new AuthResponse(false, "Removing from group failed: User is not in specified group!", null);
                            // Default
                            default -> authResponse = new AuthResponse(false, "Removing from group failed!", null);
                        }

                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        break;

                    case LIST_GROUP:
                        String groups = AuthServer.groupList(user);
                        if (groups.equals("No groups exist")) {
                            authResponse = new AuthResponse(false, groups, null);
                        } else if (groups.equals("Invalid Credentials")) {
                            authResponse = new AuthResponse(false, groups, null);
                        } else {
                            authResponse = new AuthResponse(true, groups, null);
                        }
                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        break;

                    case REMOVE_GROUP:
                        System.out.println("Remove group request received from user: " + user.name);
            
                        // Attempt to remove the group
                        int removedGroup = AuthServer.removeGroup(user, inputAuthRequest.getGroupName());
                        
                        switch(removedGroup) {
                            // Success
                            case 0 -> authResponse = new AuthResponse(true, "Successfully deleted group.", null);
                            // Fail (not admin)
                            case -1 -> authResponse = new AuthResponse(false, "Deleting group failed: Not an admin of this group!", null);
                            // Fail (invalid group)
                            case -2 -> authResponse = new AuthResponse(false, "Deleting group failed: Invalid group!", null);
                            // Fail (auth failed)
                            case -3 -> authResponse = new AuthResponse(false, "Deleting group failed: Incorrect username or password!", null);
                            // Fail (default)
                            default -> authResponse = new AuthResponse(false, "Deleting group failed!", null);
                        }

                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);

                        break;
                    // For request to get the entire list of group keys
                    case GET_GROUP_KEYS:
                        String groupName = inputAuthRequest.getGroupName();
                        int groupID = Integer.parseInt(groupName);

                        Token token = inputAuthRequest.getToken();

                        // If token signature is invalid, user should not have access to these keys
                        if(!verifyToken(token, inputAuthRequest.getSignature())) {
                            authResponse = new AuthResponse(false, groupID, null);
                        } else {
                            ArrayList<String> perms = token.getGroupPermissions();

                            // First, pad groupID (as string) if necessary
                            if (groupName.length() < 4) {
                                String temp = "";
                                int pad = 4 - groupName.length();
                                for (int i = 0; i < pad; i++) {
                                    temp += "0";
                                }
                                groupName = temp + groupName;
                            }

                            // Verify that user has relevant permissions for the groupID, checking for A or N specifically 
                            // because shouldn't have access if "D". Also, this works because the token is signed, so 
                            // (similar to if the client tries modifying their own token before entering RS) 
                            // if the user modified it in any way, the signature would not match up.
                            if(perms.contains(groupName + "A") || perms.contains(groupName + "N")) {
                                List<byte[]> l = AuthServer.getGroupKeys(groupID);
                                authResponse = new AuthResponse(true, groupID, l);
                            } else
                                authResponse = new AuthResponse(false, groupID, null);
                        }
                        sendEncrypted(authResponse, hmac, server2ClientCounter++, encryptCipher, output);
                        break;
                    default:
                        System.out.println("Invalid request received");
                        break;
                }
            }
        } catch (Exception e) {
            //System.err.println("Error: " + e.getMessage());
            //e.printStackTrace();
        } finally {
            try {
                // close the socket
                Thread.sleep(2000);
                socket.close();
            } catch (Exception e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
        }
    }

    //method for interrupting the 
    @Override
    public void interrupt() {
        try {
            System.out.println("** Closing connection with " + socket.getInetAddress() + ":" + socket.getPort() + " **");
            try {
                //close all I/O streams and socket
                if (input != null) 
                    input.close();
                if (output != null) 
                    output.close();
                if (socket != null && !socket.isClosed()) 
                    socket.close();
            } catch (Exception e) {
                System.out.println("Error closing resources");
            } 
        } finally {
            super.interrupt(); 
        }
    }


    private static void sendEncrypted(AuthResponse authResponse, Mac hmac, int server2ClientCounter, Cipher encryptCipher, ObjectOutputStream output) throws Exception { 
        authResponse.setServer2ClientCounter(server2ClientCounter);
        byte[] ciphertext = encrypt(authResponse.toString(), encryptCipher);
        AuthIntegrityMessage authIntegrityMessage = new AuthIntegrityMessage(ciphertext, hmac);
        output.writeObject(authIntegrityMessage);
        output.flush(); // Ensure the request is sent
    }

    private static AuthRequest recieveEncrypted(Mac hmac, int client2ServerCounter, Cipher decryptCipher, ObjectInputStream input) throws Exception {
        AuthIntegrityMessage authIntegrityMessage = (AuthIntegrityMessage) input.readObject();
        if (!authIntegrityMessage.verifyHmac(hmac)) {
            return null; // Integrity check failed
        }
        byte[] ciphertext = authIntegrityMessage.getCiphertext();
        String decryptedString = (String) decrypt(ciphertext, decryptCipher);
        AuthRequest authRequest = AuthRequest.fromString(decryptedString);
        if (authRequest.getClient2ServerCounter() != client2ServerCounter) {
            System.out.println("client to server counter mismatch");
            return null; // Replay attack detected
        }
        return authRequest;
    }
    
    /*
     * This method is used to sign the tokens with the AS private key
     */
    private byte[] signToken(String token) throws Exception {
        // Load the private key
        PrivateKey privateKey = ASKeypairGen.loadPrivateKey();

        // initialize the signature object with SHA-256 and PSS padding RSA
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");

        //MGF1 is the standard function used in RSA-PSS to generate padding and randomness
        //salt length of 32 adding optimal security to our signature
        //trailer field of 1 is standard for RSA-pSS idk why though.... thats just what the internet says
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initSign(privateKey);

        // Sign the token
        signature.update(token.getBytes("UTF-8"));
        byte[] signedBytes = signature.sign();

        // Return the Base64 encoded signature
        return signedBytes;

    }

    // For verifying if the sent token was signed by the server. For requesting groupKeys
    private boolean verifyToken(Token token, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA/PSS", "BC");
        verifier.initVerify(ASKeypairGen.loadPublicKey());

        // User sends over token object and original signature; to check token, we need to reserialize it
        // Could have user send over serialized token, but then we'd have to deserialize it anyways...
        verifier.update(TokenSerializer.serializeToken(token).getBytes());

        return verifier.verify(signature);
    }

    private byte[] signBytes(byte[] bytes) throws Exception {
        // Load the private key
        PrivateKey privateKey = ASKeypairGen.loadPrivateKey();

        // initialize the signature object with SHA-256 and PSS padding RSA
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");

        //MGF1 is the standard function used in RSA-PSS to generate padding and randomness
        //salt length of 32 adding optimal security to our signature
        //trailer field of 1 is standard for RSA-pSS idk why though.... thats just what the internet says
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initSign(privateKey);

        // Sign the token
        signature.update(bytes);
        byte[] signedBytes = signature.sign();

        // Return the Base64 encoded signature
        return signedBytes;

    }
}
