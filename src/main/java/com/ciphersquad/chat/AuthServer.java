package com.ciphersquad.chat;

import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.math.BigInteger;

import com.ciphersquad.chat.AuthenticationServer.*;
import com.ciphersquad.chat.ResourceServer.RSKeyStorage;
import com.ciphersquad.chat.ResourceServer.RSThread;
import com.ciphersquad.chat.client.User;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.javatuples.Pair;

public class AuthServer {
    private static final String METADATA_FILEPATH = "src/main/java/com/ciphersquad/chat/AuthenticationServer/AuthResource/metadata.json";
    private static final String GROUP_KEYS_FILEPATH = "src/main/java/com/ciphersquad/chat/AuthenticationServer/AuthResource/groupKeys.json";


    public static int SERVER_PORT = 8675;
    private static HashMap<String, String> validCredentials = new HashMap<>(); // store usr/passwrd
    // TODO: Only store 50 keys? Delete some keys when necessary
    private static HashMap<Integer, List<byte[]>> groupKeys = new HashMap<>();   // HashMap for group keys. ID -> List<encoded(keys)>. Index in list = version (versions start at 0)
    private static HashMap<String, ArrayList<String>> groupPermissions = new HashMap<>(); // groups and users who can access said groups
    private static List<String> groups;
    private static boolean keepRunning = true;
    private static HashSet<AuthThread> activeThreads = new HashSet<AuthThread>();

    public static void main(String[] args) {

        // thanks Adam J. Lee!
        boolean portSet = false;
        Security.addProvider(new BouncyCastleProvider());
        while (!portSet) {
            try {
                System.out.println("What port would you like to use for the server?");
                SERVER_PORT = Integer.parseInt(System.console().readLine());
                portSet = true;
            } catch (NumberFormatException e) {
                System.out.println("Invalid port number");
            }
        }

        try {
            // This is basically just listens for new client connections
            final ServerSocket serverSock = new ServerSocket(SERVER_PORT);

            // load credentials
            loadCredentialsFromFile(METADATA_FILEPATH);
            
            // load groupKeys
            loadKeysFromFile(GROUP_KEYS_FILEPATH);

            // A simple infinite loop to accept connections
            Socket sock = null;
            AuthThread thread = null;

            Runtime.getRuntime().addShutdownHook(new Thread() {
                public void run() {
                    keepRunning = false;
                    for (AuthThread t : activeThreads) {
                        t.interrupt();
                        System.err.println("Shutting down thread");
                    }
                    System.err.println("Authentication Server Shutting Down.");
                    serializeGroupKeys();       // update group key storage before closing server
                }
            });

            while (keepRunning) {
                sock = serverSock.accept(); // Accept an incoming connection
                thread = new AuthThread(sock); // Create a thread to handle this connection
                thread.start(); // Fork the thread
                activeThreads.add(thread);
            } // Loop to work on new connections while this
              // the accept()ed connection is handled

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

        serializeMetadata(validCredentials, groupPermissions);
    }

    // Authentication method, returns true if user exisits in
    // validcredentials and their password matches
    public static boolean authenticate(User user) {
        if (validCredentials.containsKey(user.name) && validCredentials.get(user.name).equals(user.password)) { 
            return true;
        }
        return false;
    }

    // Public method to check if the user exists
    public static boolean userExists(String username) {
        return validCredentials.containsKey(username);
    }

    // Method to add a new user
    public static boolean addNewUser(String username, String password) {
        if (!validCredentials.containsKey(username)) {
            // add the new user
            validCredentials.put(username, password);
            return true;
        }
        return false;
    }

    // load validCredentials from JSON file
    private static void loadCredentialsFromFile(String filename) {
        Gson gson = new Gson();

        try {
            File json = new File(filename);

            // If file doesn't exist, create it and write empty brackets to it
            if (!json.exists()) {
                json.createNewFile();
                FileWriter w = new FileWriter(json);
                BufferedWriter bw = new BufferedWriter(w); // Wrap w in BufferedWriter to write new line character

                bw.write("[\n\n]");
                bw.flush();

                // Close writers
                bw.close();
                w.close();
            }
        } catch (Exception e) {
            System.err.println("Error creating json file!");
        }

        try (FileReader reader = new FileReader(filename)) {
            Type userListType = new TypeToken<List<UserMetadata>>() {
            }.getType();

            // deserialize
            List<UserMetadata> userList = gson.fromJson(reader, userListType);
            groups = new ArrayList<>();

            // populate hashmaps and group list
            for (UserMetadata user : userList) {
                validCredentials.put(user.getUsername(), user.getPassword());
                groupPermissions.put(user.getUsername(), user.getGroupPermissions());

                // add all unique groups for each users
                for (String group : user.getGroupPermissions()) {
                    group = group.substring(0, 4);
                    if (!groups.contains(group)) {
                        groups.add(group);
                    }
                }
            }

        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    // method to get the permissions in an array list
    public static ArrayList<String> getPermissions(String name) {
        return groupPermissions.getOrDefault(name, new ArrayList<>());
    }

    public static Boolean deleteUser(User user) {
        // returns if the user was deleted (dont allow if password is wrong)
        if (AuthServer.authenticate(user)) {
            validCredentials.remove(user.name);
            groupPermissions.remove(user.name);

            // update db
            AuthServer.serializeMetadata(validCredentials, groupPermissions);

            return true;
        }
        return false;
    }

    // create new group, creator is Admin (A) everyone added is non-member (N)
    // Returns 0 = true, -1 = failed credentials, -2 = group number in use, -3 = too
    // large group number
    public static int makeGroup(User user, ArrayList<String> members, String groupName) {
        // System.out.println("Group members: " + members.toString());
        try {
            // returns false if the user password is wrong, and wont make a group then
            if (AuthServer.authenticate(user)) {
                System.out.println("Authenticated: " + user.name);
                // if group ID fits proper bounds
                if (groupName.length() > 0 && groupName.length() <= 4) {

                    // pad group ID if necessary
                    if (groupName.length() < 4) {
                        String temp = "";
                        int pad = 4 - groupName.length();
                        for (int i = 0; i < pad; i++) {
                            temp += "0";
                        }
                        groupName = temp + groupName;
                        // System.out.println(groupName);
                    }

                    // If group name doesn't exist
                    if (!groups.contains(groupName.substring(0, 4))) {
                        // add to users perms, they are the Admin since they are the group creators
                        groups.add(groupName);
                        ArrayList<String> userPermissions = groupPermissions.getOrDefault(user.name, new ArrayList<>());
                        userPermissions.add(groupName + "A");

                        // update users permissions
                        groupPermissions.put(user.name, userPermissions);

                        for (String member : members) {
                            // make sure member they are trying to add exists
                            if (validCredentials.containsKey(member)) {
                                ArrayList<String> memberPermission = groupPermissions.getOrDefault(member,
                                        new ArrayList<>());
                                memberPermission.add(groupName + "N");
                                groupPermissions.put(member, memberPermission);

                            } else {
                                System.out.println("User: " + member + " does not exist. Not added");
                            }
                        }

                        // update metadata
                        AuthServer.serializeMetadata(validCredentials, groupPermissions);

                        // Create list for HashMap
                        List<byte[]> groupKeyList = new ArrayList<>();

                        // Generate key
                        SecureRandom keyRand = SecureRandom.getInstance("DRBG");
                        KeyGenerator aesGenerator = KeyGenerator.getInstance("AES", "BC");
                        aesGenerator.init(128, keyRand);
                        SecretKey groupKey = aesGenerator.generateKey();

                        // Add key to List, add List to HashMap
                        groupKeyList.add(groupKey.getEncoded());
                        groupKeys.put(Integer.parseInt(groupName), groupKeyList);

                        return 0; // Return 0 on success
                    } else {
                        System.out.println("Group number in use.");
                        return -2; // Return -2 for group # in use
                    }
                    // If # > 4 digits, return error code -3
                } else {
                    return -3;
                }
                // If auth fails, return error code -1
            } else {
                return -1;
            }
        } catch (Exception e) {
            System.err.println("Error creating group: " + e.getMessage());
            //e.printStackTrace();
        }
        return -1;
    }

    // Returns 0 = true, -1 = failed credentials, -2 = user nonexistent, -3 = not
    // admin, -4 = invalid group, -5 = user alr in group
    public static int addToGroup(User user, ArrayList<String> members, String groupName) {
        // returns false if the user password is wrong, and wont add member
        // also will fail if the group or user doesnt exist or if the user isnt the
        // owner

        String addMember = members.get(0);

        if (authenticate(user)) {
            if (groupName.length() <= 4) {
                String temp = "";
                int pad = 4 - groupName.length();
                for (int i = 0; i < pad; i++) {
                    temp += "0";
                }

                groupName = temp + groupName;

                if (groups.contains(groupName.substring(0, 4))) {
                    // Check if the user is an admin of the group
                    ArrayList<String> userPermissions = groupPermissions.get(user.name);
                    boolean isAdmin = userPermissions != null && userPermissions.contains(groupName + "A");

                    if (isAdmin) {
                        // Make sure the member to be added exists
                        if (validCredentials.containsKey(addMember)) {
                            // Add the member as a non-admin (N) to the group
                            ArrayList<String> memberPermissions = groupPermissions.getOrDefault(addMember,
                                    new ArrayList<>());

                            if (!memberPermissions.contains(groupName + "N")) {// checks if user is in group yet
                                memberPermissions.add(groupName + "N");
                                groupPermissions.put(addMember, memberPermissions);

                                // Update metadata
                                serializeMetadata(validCredentials, groupPermissions);

                                System.out.println("User: " + addMember + " was added to group " + groupName);
                                return 0;

                            } else {
                                System.out.println("User " + addMember + " is already in group " + groupName);
                                return -5;
                            }
                        } else {
                            System.out.println("User: " + addMember + " does not exist.");
                            return -2;
                        }
                    } else {
                        System.out.println("User: " + user.name + " is not an admin of group " + groupName);
                        return -3;
                    }
                } else {
                    return -4;
                }
            }
            return -4;
        } else {
            return -1;
        }
    }
    // Function that loads groupKeys from JSON file, putting them into the proper index corresponding to their version
    private static void loadKeysFromFile(String filename) {
        Gson gson = new Gson();

        try {
            File json = new File(filename);

            // If file doesn't exist, create it and write empty brackets to it
            if (!json.exists()) {
                json.createNewFile();
                FileWriter w = new FileWriter(json);
                BufferedWriter bw = new BufferedWriter(w); // Wrap w in BufferedWriter to write new line character

                bw.write("[\n\n]");
                bw.flush();

                // Close writers
                bw.close();
                w.close();
            }
        } catch (Exception e) {
            System.err.println("Error creating json file!");
        }

        // Read JSON from file, convert to PK and store in HashMap ("<IP>" -> PK)
        try (FileReader r = new FileReader(filename);) {

            // Extract keys.json as JsonArray
            JsonArray arr = gson.fromJson(r, JsonArray.class);

            // For each (IP, ver, PK) tuple in keys.json, decode key and store in mapping
            for (int i = 0; i < arr.size(); i++) {
                JsonObject obj = arr.get(i).getAsJsonObject();

                // Extract encoded key as ASKeyStorage object (which is just an object with IP, version, and byte array variables)
                ASKeyStorage encodedKey = gson.fromJson(obj, ASKeyStorage.class);

                //SecretKey secretKey = new SecretKeySpec(encodedKey.getKey(), "AES");

                int id = obj.get("id").getAsInt();

                // Create list in mapping if it doesn't already exist
                if(!groupKeys.containsKey(id))
                    groupKeys.put(id, new ArrayList<>());

                // Store key in list
                groupKeys.get(id).add(obj.get("version").getAsInt(), encodedKey.getKey());
            }
        } catch (Exception e) {
            //e.printStackTrace();
            System.err.println("Error reading group keys from file!");
        }
    }

    // Returns a list of all current keys given user's permissions. Returns null on failure
    // Returns [Group # -> (SecretKey, ver)]
    public static HashMap<Integer, byte[][]> getSecretKeyMap(ArrayList<String> perms) {
        try {
            HashMap<Integer, byte[][]> map = new HashMap<>();
            for(String p : perms) {
                int id = Integer.parseInt(p.substring(0, 4));

                List<byte[]> l = groupKeys.get(id);
                int lSize = l.size();
                if(l != null && lSize != 0)
                    // Map is ID -> {encoded SecretKey latest ver, ver #}
                    map.put(id, new byte[][] { l.get(lSize-1), String.valueOf((lSize)).getBytes() });
            }
            return map;
        } catch(Exception e) {
            System.err.println("Error in getSecretKeyMap!");
            //e.printStackTrace();
            return null;
        }
    }

    // this will list the groups
    public static String groupList(User user) {
        ArrayList<String> groups = groupPermissions.get(user.name);
        List <String> memberGroups = new ArrayList<>();
        if (groups == null){
            return "";
        }
        for (String group: groups){
            memberGroups.add(group.substring(0, 4));
        }

        return memberGroups.toString();
    }

    // remove user from group (0=true, -1=failed auth, -2=nonexistent group, -3=not
    // admin, -4=user nonexistent, -5=user not in group)
    public static int removeFromGroup(User user, ArrayList<String> member, String groupName) {
        // returns false if the user password is wrong, and wont remove member
        // also will fail if the group or userdoesnt exist or if the user isnt the owner
        String removeMember = member.get(0);

        if (authenticate(user)) {
            if (groupName.length() < 4) {
                String temp = "";
                int pad = 4 - groupName.length();
                for (int i = 0; i < pad; i++) {
                    temp += "0";
                }

                groupName = temp + groupName;
            }

            // check group exists
            if (groups.contains(groupName.substring(0, 4))) {
                // check if the user is the Admin (A) of this group
                ArrayList<String> userPermissions = groupPermissions.get(user.name);
                if (userPermissions != null && userPermissions.contains(groupName + "A")) {
                    // make sure the member exists and has the group in their permissions
                    if (groupPermissions.containsKey(removeMember)) {
                        ArrayList<String> memberPermissions = groupPermissions.get(removeMember);
                        if (memberPermissions != null && memberPermissions.contains(groupName + "N")) {
                            // Remove the group from the members permissions
                            memberPermissions.remove(groupName + "N");
                            groupPermissions.put(removeMember, memberPermissions);
                            System.out.println("User: " + member + " was removed from the group: " + groupName);
                        } else {
                            System.out.println("User: " + member + " is not part of the group: " + groupName);
                            return -5;
                        }
                    } else {
                        System.out.println("User: " + member + " does not exist.");
                        return -4;
                    }

                    // Update metadata
                    AuthServer.serializeMetadata(validCredentials, groupPermissions);

                    try {
                        // Create new symmetric key for group, because user was removed
                        SecureRandom keyRand = SecureRandom.getInstance("DRBG");
                        KeyGenerator aesGenerator = KeyGenerator.getInstance("AES", "BC");
                        aesGenerator.init(128, keyRand);
                        SecretKey groupKey = aesGenerator.generateKey();

                        // Add to list for specific ID
                        groupKeys.get(Integer.parseInt(groupName)).add(groupKey.getEncoded());
                    } catch(Exception e) {
                        // Hopefully this doesn't happen... Little handling for it as of now. 
                        // User would still be removed, but no new group key would be created
                        System.out.println("Error! Failed to create group key!");
                        return -6;
                    }

                    return 0; // Successful removal
                } else {
                    System.out.println("You do not have permission to remove members from this group.");
                    return -3; // User not admin
                }
            } else {
                return -2;
            }
        }
        return -1;
    }

    public static int removeGroup(User user, String groupName) {
        if (authenticate(user)) {
            // Ensure groupName is padded to 4 digits
            if (groupName.length() < 4) {
                String temp = "";
                int pad = 4 - groupName.length();
                for (int i = 0; i < pad; i++) {
                    temp += "0";
                }
                groupName = temp + groupName;
            }

            // Check if group exists
            if (groups.contains(groupName)) {
                // Check if the user is the Admin of this group
                ArrayList<String> userPermissions = groupPermissions.get(user.name);
                if (userPermissions != null && userPermissions.contains(groupName + "A")) {
                    // For every user in the group, update their permissions to "D" (Deleted)
                    for (String member : validCredentials.keySet()) {
                        ArrayList<String> memberPermissions = groupPermissions.getOrDefault(member, new ArrayList<>());
                        for (int i = 0; i < memberPermissions.size(); i++) {
                            if (memberPermissions.get(i).contains(groupName)) {
                                String permissionType = memberPermissions.get(i).substring(4);
                                // Update permissions to "D" if they have "A" or "N"
                                if ("A".equals(permissionType) || "N".equals(permissionType)) {
                                    memberPermissions.set(i, groupName + "D");
                                }
                            }
                        }
                        groupPermissions.put(member, memberPermissions);
                    }

                    // Remove the group from the group list
                    groups.remove(groupName);

                    // Update metadata
                    serializeMetadata(validCredentials, groupPermissions);
                    // TODO: Don't think groupKeys json needs to be updated here... But verify that

                    // Remove ID for groupKeys, no longer needed
                    groupKeys.remove(Integer.parseInt(groupName));

                    System.out.println("Group " + groupName + " has been deleted.");
                    return 0; // Success
                } else {
                    System.out.println("User " + user.name + " is not an admin of group " + groupName);
                    return -1; // Not an admin
                }
            } else {
                System.out.println("Group " + groupName + " does not exist.");
                return -2; // Group not found
            }
        } else {
            System.out.println("User authentication failed.");
            return -3; // Authentication failed
        }
    }

    // for writing to our metadata file...
    public static void serializeMetadata(HashMap<String, String> validCredentials,
            HashMap<String, ArrayList<String>> groupPermissions) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        List<UserMetadata> userMetadataList = new ArrayList<>();

        // parse each user and create user metadata objects to write to file
        for (String username : validCredentials.keySet()) {
            String password = validCredentials.get(username);
            ArrayList<String> permissions = groupPermissions.get(username);

            // Create UserMetadata object
            UserMetadata userMetadata = new UserMetadata(username, password, permissions);
            userMetadataList.add(userMetadata);
        }

        // write to the file
        try (FileWriter writer = new FileWriter(METADATA_FILEPATH, false)) {
            gson.toJson(userMetadataList, writer);
            System.out.println("User metadata has been updated.");
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    // for writing groupKeys to metadata file
    private static void serializeGroupKeys() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        List<ASKeyStorage> ASKeyList = new ArrayList<>();

        // for each groupID
        for(int id : groupKeys.keySet()) {
            // Parse each key
            List<byte[]> keyList = groupKeys.get(id);
            for(int j = 0; j < keyList.size(); j++) {
                //Convert to ASKeyStorage
                ASKeyStorage kStorage = new ASKeyStorage(id, j, keyList.get(j));

                // Add to List of ASKeyStorage
                ASKeyList.add(kStorage);
            }
        }

        // Write newly created list to file
        try (FileWriter writer = new FileWriter(GROUP_KEYS_FILEPATH, false)) {
            gson.toJson(ASKeyList, writer);
            System.out.println("Group key metadata has been updated.");
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    // For Auth request to get keys
    public static List<byte[]> getGroupKeys(int groupID) {
        return groupKeys.get(groupID);
    }

    /*
     * Iterate over groupPermissions to find users with the groupName
     * present in their groupPermissions ArrayList<String> and removing
     */
    public static void removeDPermissionFromAllUsers(String groupName) {
        // check all users in hashset for groupname
        for (String username : groupPermissions.keySet()) {
            ArrayList<String> permissions = groupPermissions.get(username);

            // Check if the user has the specific group with "D" permission
            if (permissions != null) {
                // use an iterator to avoid ConcurrentModificationException
                permissions.removeIf(permission -> permission.equals(groupName));

                // store updated permissions as new permissions
                groupPermissions.put(username, permissions);
            }
        }
        // probably should update database now too
        serializeMetadata(validCredentials, groupPermissions);
    }
    
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static SecretKeySpec deriveAESKey(byte[] sharedSecret) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, null, null));
        byte[] aesKey = new byte[32]; // 256 bits
        hkdf.generateBytes(aesKey, 0, aesKey.length);
        return new SecretKeySpec(aesKey, "AES");
    }

    public static SecretKeySpec deriveHMacKey (byte[] sharedSecret) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, null, null));
        byte[] hmacKey = new byte[32]; // 256 bits
        hkdf.generateBytes(hmacKey, 0, hmacKey.length);
        return new SecretKeySpec(hmacKey, "HmacSHA256");
    }

    public static byte[] encrypt(String plaintext, Cipher encryptCipher) throws Exception {
        return encryptCipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(byte[] ciphertext,  Cipher decryptCipher) throws Exception {
        byte[] plaintext = decryptCipher.doFinal(ciphertext);
        return new String(plaintext);
    }


    public static SecretKeySpec deriveEncryptKey(byte[] sharedSecret) {
        byte[] modifiedSharedSecret = new byte[16];
        byte by = (byte) 'e';
        for (int i = 0; i < 16; i++) {
            modifiedSharedSecret[i] = (byte) (sharedSecret[i] ^ by);
        }
        SecretKeySpec aesKey = deriveAESKey(modifiedSharedSecret);

        return aesKey;
    }

    public static SecretKeySpec deriveIntegrityKey(byte[] sharedSecret) {
        byte[] modifiedSharedSecret = new byte[16];
        byte by = (byte) 'i';
        for (int i = 0; i < 16; i++) {
            modifiedSharedSecret[i] = (byte) (sharedSecret[i] ^ by);
        }
        SecretKeySpec aesKey = deriveHMacKey(modifiedSharedSecret);
        return aesKey;
    }
}
