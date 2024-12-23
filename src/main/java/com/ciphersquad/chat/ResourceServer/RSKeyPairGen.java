package com.ciphersquad.chat.ResourceServer;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Scanner;

import com.google.gson.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSKeyPairGen {
  private static String pathName = "src/main/java/com/ciphersquad/chat/ResourceServer/RSKeys/";

  public static void main(String[] args)
      throws NoSuchAlgorithmException, NoSuchProviderException, IOException {

    // Setup
    Security.addProvider(new BouncyCastleProvider());
    Gson gson = new Gson(); // pretty printing takes too much lines
    Scanner s = new Scanner(System.in);

    // Get IP Address
    System.out.println("Enter IP Address for server");
    String ip = s.nextLine();
    s.close();
    ArrayList<RSKeyStorage> allPubKeys;
    // ArrayList<RSKeyStorage> allPriKeys;
    // Read existing keys
    try {
      allPubKeys = new ArrayList<RSKeyStorage>(
          Arrays.asList(gson.fromJson(new FileReader(pathName + "rs_public_key.json"), RSKeyStorage[].class)));

      // allPriKeys = new ArrayList<RSKeyStorage>(
      // Arrays.asList(gson.fromJson(new FileReader(pathName + "rs_private_key.json"),
      // RSKeyStorage[].class)));
    } catch (FileNotFoundException e) {
      allPubKeys = new ArrayList<RSKeyStorage>();
      // allPriKeys = new ArrayList<RSKeyStorage>();
    }

    // Generate key and output
    KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    rsaGenerator.initialize(4096); // 4096 Bit Key Pair
    KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();

    allPubKeys.add(new RSKeyStorage(ip, rsaKeyPair.getPublic().getEncoded()));
    FileWriter pubIn = new FileWriter(pathName + "rs_public_key.json");
    pubIn.write(gson.toJson(allPubKeys.toArray()));
    pubIn.close();

    // allPriKeys.add(new RSKeyStorage(ip,));
    BufferedOutputStream priIn = new BufferedOutputStream(new FileOutputStream(pathName + "rs_private_key.txt"));
    priIn.write(rsaKeyPair.getPrivate().getEncoded());
    priIn.close();
  }
}
