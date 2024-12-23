package com.ciphersquad.chat.client;

import java.util.Scanner;

public class AuthServerClient {
    int port;
    public AuthServerClient() {
        port = -1;
    }
    public String getTolken(User user) { //returns a token
        if (user.name.equals("admin") && user.password.equals("admin")) {
            return "1234567890";
        } else {
            return "";
        }
    }
    public void setPort(int port) {
        this.port = port;
    }
    public int getPort() {
        return port;
    }
}
