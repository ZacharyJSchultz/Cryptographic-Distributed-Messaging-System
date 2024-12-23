package com.ciphersquad.chat.AuthenticationServer;

/*
 *      This class is used for writing metaData to .json file
 *      It accepts a user, and serializes that user onto a metadata.json 
 *      file under AuthenticationServer/AuthResource
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.ciphersquad.chat.client.User;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Type;

public class MetadataSerializer {
    private static final String METADATA_FILE = "src/main/java/com/ciphersquad/chat/AuthenticationServer/AuthResource/metadata.json";

    UserMetadata userMetadata;

    public static void serializeMetadata(User user) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        List<UserMetadata> userMetadataList = new ArrayList<>();

        try (FileReader reader = new FileReader(METADATA_FILE)) {
            Type userListType = new TypeToken<List<UserMetadata>>(){}.getType();
            userMetadataList = gson.fromJson(reader, userListType);

            // If the file is empty, create a new list
            if (userMetadataList == null) {
                userMetadataList = new ArrayList<>();
            }
        } catch (FileNotFoundException e) {
            System.out.println("Metadata file not found");
        } catch (IOException e) {
            e.printStackTrace();
        }

        UserMetadata userMetadata = new UserMetadata(user.name, user.password, user.token.getGroupPermissions());
        userMetadataList.add(userMetadata);
        
        //write it to file
        try (FileWriter writer = new FileWriter(METADATA_FILE)) {
            gson.toJson(userMetadataList, writer);
            System.out.println("User metadata has been updated ");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

