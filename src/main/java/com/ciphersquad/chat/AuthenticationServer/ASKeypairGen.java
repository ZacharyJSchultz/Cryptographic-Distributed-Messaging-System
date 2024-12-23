package com.ciphersquad.chat.AuthenticationServer;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * This class is used for generating the keypair for the AS
 */
public class ASKeypairGen {
    //Constants
    private static final String PRIVATE_KEY_PATH = "src/main/java/com/ciphersquad/chat/AuthenticationServer/AuthResource/private_key.txt";
    private static final String PUBLIC_KEY_PATH = "src/main/java/com/ciphersquad/chat/AuthenticationServer/AuthResource/public_key.txt";
    private static final int RSA_KEY_SIZE = 4096;

    public static void main(String args[]) throws 
            NoSuchAlgorithmException, NoSuchProviderException, IOException{

        Security.addProvider(new BouncyCastleProvider()); 

        //generate private and public keypair for AS
        KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        rsaGenerator.initialize(RSA_KEY_SIZE); // 4096 Bit Key Pair
        KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
        
        saveKeyToFile(PRIVATE_KEY_PATH, rsaKeyPair.getPrivate().getEncoded());
        saveKeyToFile(PUBLIC_KEY_PATH, rsaKeyPair.getPublic().getEncoded());

    }

    //save keys to file 
    private static void saveKeyToFile(String fileName, byte[] keyBytes) throws IOException {
        String encodedKey = Base64.getEncoder().encodeToString(keyBytes);
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(encodedKey);
        }
    }

    //load private key from file
    public static PrivateKey loadPrivateKey() throws Exception {
        byte[] keyBytes = readKeyFromFile(PRIVATE_KEY_PATH);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePrivate(keySpec);
    }

    // Load a public key from file
    public static PublicKey loadPublicKey() throws Exception {
        byte[] keyBytes = readKeyFromFile(PUBLIC_KEY_PATH);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePublic(keySpec);
    }

    // Read in the key from the file as a byte stream 
    private static byte[] readKeyFromFile(String fileName) throws IOException {
        String encodedKey = new String(Files.readAllBytes(Paths.get(fileName)));
        return Base64.getDecoder().decode(encodedKey);
    }
}
