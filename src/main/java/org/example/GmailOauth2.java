package org.example;

import com.amazonaws.auth.AWSCredentials;

import com.amazonaws.auth.BasicAWSCredentials;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.*;

import com.amazonaws.util.StringUtils;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.api.services.gmail.model.Label;
import com.google.api.services.gmail.model.ListLabelsResponse;
import org.joda.time.Days;
import org.joda.time.Hours;

import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Hello world!
 *
 */
public class GmailOauth2
{
    private static final String APPLICATION_NAME = "Gmail API Java Quickstart";
    private static final String TOKENS_DIRECTORY_PATH = "tokens";
    private static final String CREDENTIALS_FILE_PATH = "/home/satish/google-sdk-gmail/oauth2-using-gmail/src/main/credentials.json";

   private static final String USER = "lifesizetestuser8@gmail.com";

  //private static final String USER = "me";



    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final List<String> SCOPES = Collections.singletonList(GmailScopes.GMAIL_LABELS);
   // private static final String AWS_ACCESS_KEY_ID = null; ;
   private static Properties prop = new Properties();

// This functionality  gets access token ,refresh token from GCP console by passing  client id, client secrets
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException, FileNotFoundException {


        String json = "{\n" +
                "  \"web\": {\n" +
                "    \"client_id\": \"113078440933-kdcp4qct7h271eopjoqdrcpdlda4he2i.apps.googleusercontent.com\",\n" +
                "    \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n" +
                "    \"token_uri\": \"https://oauth2.googleapis.com/token\",\n" +
                "    \"client_secret\": \"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\"\n" +
                "  }\n" +
                "}";
        Reader string_reader = new StringReader(json);
        Reader credentials_file_reader =  new FileReader(CREDENTIALS_FILE_PATH);
        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY,string_reader);
        System.out.println("::::clientSecrets:::"+clientSecrets);
        // Property file path
        FileReader fileRead = new FileReader("/home/satish/google-sdk-gmail/oauth2-using-gmail/src/main/java/org/example/application.properties");
         prop = new Properties();
        prop.load(fileRead);
        System.out.println("::::Database Table Name::::"+prop.getProperty("db_table"));
        // Build flow and trigger user authorization request.

        AmazonDynamoDB amazonDB = authenticateDynoDBCredentials(HTTP_TRANSPORT);
        DynamoDB dynamoDB = new DynamoDB(amazonDB);
        Table table = dynamoDB.getTable(prop.getProperty("db_table"));
          Item item = table.getItem("tenantId",prop.getProperty("tenant_id"));
        String createdDateFromTbl = item.getString("created");
        System.out.println("::::createdDateFromTbl:::"+createdDateFromTbl);
        Credential credential= null;



         Credential credNoRefreshToken= null;
         // This condition is executed first time when there is no Items present in database
        if(createdDateFromTbl == "" || createdDateFromTbl.equals(null)) {
            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                    HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                    .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                    .setAccessType("offline").setApprovalPrompt("force")
                    .build();
            System.out.println("::::flow:::" + flow.getAccessType());
            System.out.println("::::flow:::" + flow.getTokenServerEncodedUrl());
            LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
            //Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize(USER);
            credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize(USER);
            System.out.println(":::::credential:::::" + credential);


            System.out.println("ClientId: " + clientSecrets.getDetails().getClientId());
            System.out.println("ClientSecret: " + clientSecrets.getDetails().getClientSecret());
            System.out.println("access_token: " + credential.getAccessToken());
            System.out.println("refresh_token: " + credential.getRefreshToken());
            System.out.println("::::::Current Time::::" + LocalDateTime.now().toString());
            // Store token into AWS DB


            //return credential;

        }else{
            System.out.println("In Else statement");
            String modifiedDateFromTbl = item.getString("modified");
            LocalDateTime timeFromDB = LocalDateTime.parse(modifiedDateFromTbl);
            System.out.println("::::LocalDateTime:::"+timeFromDB);
            ZonedDateTime zdt = ZonedDateTime.of(timeFromDB, ZoneId.systemDefault());
            long dbTimeInMillis = zdt.toInstant().toEpochMilli();
            System.out.println("::::Time from Dynamo Db in millis:::"+dbTimeInMillis);
            LocalDateTime localDateTime = LocalDateTime.now();
            System.out.println("::::Local Date Time ::"+localDateTime);
            ZonedDateTime zdt1 = ZonedDateTime.of(localDateTime, ZoneId.systemDefault());
            long currentTimeInMillis = zdt1.toInstant().toEpochMilli();
            System.out.println("::::Local Date Time in millis:::"+currentTimeInMillis);

           // This condition is executed when  access token has expired after 1 hour time and
            // refresh token will be used to get new access token
             if(currentTimeInMillis - dbTimeInMillis >3600000){
                 System.out.println(" ::::Use refresh Token to get Access Token :::::");
                 String refreshToken = item.getString("refresh-token");
                 System.out.println(" ::::refresh-token :::::"+refreshToken);
                 String accessTokenOlder = item.getString("access-token");
                 //String accessTokenOlder = "KG49dlWI1fUz5aDq2aONn6qX9oT8hY35zK7h1WRz";
                 System.out.println(" ::::access-token old :::::"+accessTokenOlder);
                 GoogleCredential accessTokenUsingRefresh = new GoogleCredential.Builder()
                         .setClientSecrets("113078440933-kdcp4qct7h271eopjoqdrcpdlda4he2i.apps.googleusercontent.com", "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")
                         .setJsonFactory(JSON_FACTORY).setTransport(HTTP_TRANSPORT).build()
                         .setRefreshToken(refreshToken).setAccessToken(accessTokenOlder);
                 System.out.println(" ::::Use refresh Token to get Access Token :::::"+accessTokenUsingRefresh.getRefreshToken());
                 System.out.println(" ::::Use refresh Token to get Access Token :::::"+accessTokenUsingRefresh.getAccessToken());
                 //LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
                  credential = accessTokenUsingRefresh;

                 // This condition is executed when  access token has not expired (less than 1 hour time)
             }else{

                 System.out.println(":::Use Access Token when it has not expired::::");
                 GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                         HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                         .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                         .setAccessType("offline").setApprovalPrompt("force")
                         .build();
                 System.out.println("::::flow:::" + flow.getAccessType());
                 System.out.println("::::flow:::" + flow.getTokenServerEncodedUrl());
                 LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
                 //Credential credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize(USER);
                 credential = new AuthorizationCodeInstalledApp(flow, receiver).authorize(USER);
                 System.out.println(" ::::Credential Access Token :::::"+credential.getAccessToken());
                 System.out.println(" :::: Credential Refresh Token :::::"+credential.getRefreshToken());
             }
        }

        return credential;
    }


        // This functionality uses access key, secret key for connecting to aws and then using
       //amazon  dynamo db interface for creating reference for a particular region

    private static AmazonDynamoDB authenticateDynoDBCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
           // Credential cred = getCredentials(HTTP_TRANSPORT);
            //String accessToken = cred.getAccessToken();
           // String refreshToken = cred.getRefreshToken();
        System.out.println("::::::authenticateDynoDBCredentials()::::: " );
           final String AWS_ACCESS_KEY_ID = StringUtils.trim(prop.getProperty("AWS_ACCESS_KEY_ID"));
           final String AWS_SECRET_ACCESS_KEY = StringUtils.trim( prop.getProperty("AWS_SECRET_ACCESS_KEY"));

        AWSCredentials awsCred = new BasicAWSCredentials(AWS_ACCESS_KEY_ID ,AWS_SECRET_ACCESS_KEY);
        System.out.println("::::::aws access key::::: "+awsCred.getAWSAccessKeyId() );
        System.out.println("::::::aws secret key::::: "+awsCred.getAWSSecretKey() );

        AmazonDynamoDB dynamoDB = AmazonDynamoDBClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
       return dynamoDB;
    }
    // This functionality is used for saving data into dynamo database using amazon dynamo db reference
     private static void saveDataIntoDynoDB(final NetHttpTransport HTTP_TRANSPORT,AmazonDynamoDB db) throws IOException, SQLException {
         DynamoDB dynamoDB = new DynamoDB(db);
         Credential cred = getCredentials(HTTP_TRANSPORT);
         System.out.println("::::::saveDataIntoDynoDB cred:::"+cred);
         Table table = dynamoDB.getTable(prop.getProperty("db_table"));


         Item item = new Item().withPrimaryKey("tenantId",prop.getProperty("tenant_id")).
                 withString("access-token",cred.getAccessToken()).withString("refresh-token",cred.getRefreshToken())
                 .withString("email",USER).withString("created", LocalDateTime.now().toString())
                 .withString("modified",LocalDateTime.now().toString());
             table.putItem(item);


     }
     // This functionality is to display data present in dynamo database
      public static void displayDynamoDb(AmazonDynamoDB db){
            System.out.println("::::::displayDynamoDb()"+db.listTables());
         DynamoDB dynamoDB = new DynamoDB(db);

           Table table = dynamoDB.getTable(prop.getProperty("db_table"));
         Item item = table.getItem("tenantId", prop.getProperty("tenant_id"));
          System.out.println("::::Table Data to Display::::::");
         System.out.println(item.toJSONPretty());


      }
    public static void main(String... args) throws IOException, GeneralSecurityException, SQLException {
        // Build a new authorized API client service.
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();
            // Access to Dynamo Db
        AmazonDynamoDB db = authenticateDynoDBCredentials(HTTP_TRANSPORT);
       System.out.println("::::Dyno Db Instance::::"+db);
         displayDynamoDb(db);
         saveDataIntoDynoDB(HTTP_TRANSPORT,db);
        // Print the labels in the user's account.
        //String user = USER;
        String user ="me";
        ListLabelsResponse listResponse = service.users().labels().list(user).execute();
        List<Label> labels = listResponse.getLabels();
        if (labels.isEmpty()) {
            System.out.println("No labels found.");
        } else {
            System.out.println("Labels:");
            for (Label label : labels) {
                if (label.getType().toLowerCase().equals("user")) {
                    System.out.println(" - " + label.getName() + " \t\t " + label.getId());
                } else {
                    System.out.println(" - " + label.getName());
                }
                // System.out.printf("- %s\n", label.getName(), label.getType());
            }
        }
    }
}
