package com.ciphersquad.chat.AuthenticationServer;
import com.google.gson.Gson;

public class TokenSerializer {
    
    // Serialize token
    public static String serializeToken(Token token) {
        Gson gson = new Gson();
        return gson.toJson(token);  // converts token to JSON string
    }

    // Deserialize token
    public static Token deserializeToken(String jsonToken) {
        Gson gson = new Gson();
        return gson.fromJson(jsonToken, Token.class);  // converts JSON string back to Token
    }
}
