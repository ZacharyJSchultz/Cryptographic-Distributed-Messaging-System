package com.ciphersquad.chat;

import java.util.Scanner;
import java.util.HashMap;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.security.Security;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.ciphersquad.chat.ResourceServer.RSKeyStorage;
import com.ciphersquad.chat.client.*;

public class App {

  // Maps "<IP>" -> public key
  public static HashMap<String, RSAPublicKey> publicKeys = new HashMap<String, RSAPublicKey>();
  public static String ip = "";

  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    if (!readPublicKeys()) {
      System.err.println("Error! No public keys exist. Please input at least one public key into keys.json.");
      System.err.println("Shutting down...");
      System.exit(1);
    }

    Scanner scanner = new Scanner(System.in);

    User user = new User();
    AuthServerClient authServer = new AuthServerClient();

    // For Resource Server testing, change Screen to RESOURCE
    Screen currentScreen = Screen.LOGIN;

    authServer.setPort(AuthServer.SERVER_PORT);
    while (currentScreen != Screen.EXIT) {
      switch (currentScreen) {
        // case AUTH_SERVER_PORT:
        // currentScreen = authServer.updatePort(scanner);
        // break;

        case LOGIN:
          currentScreen = AuthServerScreen.loginScreen(user, scanner, authServer);
          break;

        case RESOURCE:
          ResourceServerApp rsa = new ResourceServerApp(user, scanner);
          currentScreen = rsa.run();
          break;

        default:
          System.out.println("Unknown screen");
          currentScreen = Screen.EXIT;
          break;
      }
    }
  }

  private static boolean readPublicKeys() {
    // String filePath =
    // "./src/main/java/com/ciphersquad/chat/client/ClientResource/keys.json";
    String filePath = "./src/main/java/com/ciphersquad/chat/ResourceServer/RSKeys/rs_public_key.json";

    // Check if file exists. If it doesn't, create it
    try {
      File file = new File(filePath);

      if (!file.exists()) {
        file.createNewFile();

        // Write array brackets in file (so user can put JSON objects inside)
        FileWriter w = new FileWriter(file);
        BufferedWriter bw = new BufferedWriter(w); // Wrap w in BufferedWriter to write new line character

        bw.write("[\n\n]");
        bw.flush();

        // Close writers
        bw.close();
        w.close();

        return false;
      }
    } catch (IOException e) {
      System.err.println("Error creating keys.json! Aborting!");
      return false;
    }

    // Read JSON from file, convert to PK and store in HashMap ("<IP>" -> PK)
    try (FileReader r = new FileReader(filePath);) {
      Gson gson = new Gson();

      // Extract keys.json as JsonArray
      JsonArray arr = gson.fromJson(r, JsonArray.class);

      // For each (IP, PK) pair in keys.json, decode PK and store in mapping
      for (int i = 0; i < arr.size(); i++) {
        JsonObject obj = arr.get(i).getAsJsonObject();

        // Extract encoded PK as RSKeyStorage object (which is just an object with IP
        // and byte array variables)
        RSKeyStorage encodedPk = gson.fromJson(obj, RSKeyStorage.class);

        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA", "BC")
            .generatePublic(new X509EncodedKeySpec(encodedPk.getKey()));

        // Store in mapping
        publicKeys.put(obj.get("server").getAsString(), publicKey);
      }

      return true;
    } catch (Exception e) {
      //e.printStackTrace();
      System.err.println("Error reading public keys from file!");
      return false;
    }
  }
}