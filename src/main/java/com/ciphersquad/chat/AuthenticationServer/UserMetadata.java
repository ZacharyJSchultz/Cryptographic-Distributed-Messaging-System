package com.ciphersquad.chat.AuthenticationServer;

import java.util.ArrayList;

/*
 * This will be used for writing user meta data to .json file
 * to add more metadata we just have to update this file...?
 * 
 */

public class UserMetadata {
    private String username;
    private String password;
    private ArrayList<String> groupPermissions;

    public UserMetadata(String username, String password, ArrayList<String> groupPermissions) {
        this.username = username;
        this.password = password;
        this.groupPermissions = groupPermissions;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public ArrayList<String> getGroupPermissions() {
        return groupPermissions;
    }

    public void setGroupPermissions(ArrayList<String> groupPermissions) {
        this.groupPermissions = groupPermissions;
    }
}
