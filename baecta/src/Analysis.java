import java.util.*;
import java.net.URL;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;

public class Analysis {
    private static String ipQualityApiEndpoint = "https://ipqualityscore.com/api/json/url/wXy2VbYm22QOOgEMo3N5k4V1sBsGpGcX/";
    private static String haveIBeenPawnedEndpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/";
    private static final int threadQuantity = 4;
    public static int maliciousUrlCounter = 0;

    public static String getIpQualityApiEndpoint(){
        return ipQualityApiEndpoint;
    }
    public static String getApiConnection(String stringUrl, String headerName, String headerValue) throws Exception {
        URL url = new URL(stringUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        if (!headerName.equals("")) {
            connection.setRequestProperty(headerName, headerValue);
        }
        int status = connection.getResponseCode();
        if (status == 200) {
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = in.readLine()) != null)
                content.append(inputLine);
            in.close();
            return content.toString();
        }
        return null;
    }

    public static void checkMaliciousUrls() throws Exception{
        Iterator<String> itr = UserData.getBrowserHistory().iterator();
        int noThreads = UserData.browserHistory.size()/threadQuantity;
        if(noThreads == 0 )
            noThreads = 1;
        for(int i = 0 ; i < noThreads; i++){
            ArrayList<String> browserHistoryList = new ArrayList<String>();
            int temp = threadQuantity;
            while(itr.hasNext() && temp>0){
                browserHistoryList.add(itr.next());
                temp--;
            }
            if(i==noThreads-1)
                while(itr.hasNext())
                    browserHistoryList.add(itr.next());

            Thread malicioiusUrlCheckerThread = new Thread(new MalicioiusUrlCheckerRunnable(browserHistoryList));
            malicioiusUrlCheckerThread.start();
        }

        while(Analysis.maliciousUrlCounter < UserData.getBrowserHistory().size()){
            System.out.print("[*] Scanning Malicious URL's: " + maliciousUrlCounter + "/" + UserData.getBrowserHistory().size() + "\r");
            Thread.sleep(10);
        }
        System.out.println("[*] Scanning Malicious URL's: " + UserData.getBrowserHistory().size() +"/" + UserData.getBrowserHistory().size());
    }

    public static void checkPublicDataBreaches() {
        try {
            HashSet<String> emails = new HashSet<String>();
            Iterator<Credential> credentialIterator = UserData.getCredentials().iterator();
            while (credentialIterator.hasNext()) {
                String username = credentialIterator.next().getUsername();
                if (checkEmail(username))
                    emails.add(username.toLowerCase());
            }

            Iterator<String> emailIterator = emails.iterator();
            int i = 0;
            while (emailIterator.hasNext()) {
                System.out.print("[*] Checking credentials in public data breaches: " + i + "/" + emails.size() + "\r");
                String email = emailIterator.next();
                String output = getApiConnection(haveIBeenPawnedEndpoint + email, "hibp-api-key","398bba8c95cc4db4a23138af3037a496");
                if (output != null) {
                    JSONParser parser = new JSONParser();
                    JSONArray root = (JSONArray) parser.parse(output);
                    DataWriter.addBreachedWebsite(root, email);
                }
                Thread.sleep(1500);
                i++;
            }
            System.out.println("[*] Checking credentials in public data breaches: " + i + "/" + emails.size());
        } catch (Exception e) {
            System.out.println("[*] Exception occurred: " + e + "\n[*] Terminating");
            // System.exit(0);
        }
    }

    static Boolean checkEmail(String username) {
        String regex = "^(.+)@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(username);
        return matcher.matches();
    }

    public static void calculatePasswordStrength() throws Exception{
        System.out.println("[*] Checking password strength");
        Iterator<Credential> credential_Iterator = UserData.getCredentials().iterator();
        while (credential_Iterator.hasNext()) {
            Credential current_credential = credential_Iterator.next();
            String password = current_credential.getPassword();
            String passwordReccomendation, timeTakenToCrack;
            int totalPasswordScore, lengthScore, commonPasswordsScore;
            long secondsToCrack;
            int [] varianceScores;
            int [] charTypeScores;
            
            if (password.length() == 0)
                continue;
            
            secondsToCrack = (long) ((long) Math.pow(50, password.length())*0.000000001);

            timeTakenToCrack = ConvertSectoDay(secondsToCrack);
            
            lengthScore = getPasswordLengthScore(password);
            varianceScores = getCharVarianceScores(password);
            charTypeScores = getCharTypeScores(password);
            commonPasswordsScore = getCommonPasswordsScore(password);

            if(commonPasswordsScore == 0){
                totalPasswordScore = 0;
                passwordReccomendation = "Your password was there in 2021 most common passwords. Change it immmediately";
                timeTakenToCrack = "Less than 10 minutes";
            }
            else{
                totalPasswordScore = lengthScore + varianceScores[0] + varianceScores[1] + charTypeScores[0] + commonPasswordsScore;
                if(totalPasswordScore > 95){
                    totalPasswordScore = 100;
                    passwordReccomendation = "Your password is perfect";
                }
                else                
                    passwordReccomendation = getPasswordReccomendation(lengthScore, varianceScores, charTypeScores);
            }
            DataWriter.addCredential(current_credential.getUsername(), password, totalPasswordScore, passwordReccomendation,timeTakenToCrack, current_credential.getUrl());
        }
    }
    private static int getPasswordLengthScore(String password){
        int password_length = password.length();
        if (password_length < 8) {
            return ((password_length + 2) * 3);
        }
        return 30;
    }
    private static int[] getCharVarianceScores(String password){
        int highest_ch_count = 0, singleCharScore, multicharScore;
        HashMap<Character, Integer> count = new HashMap<>();
        for (int i = 0; i < password.length(); i++) {
            if (count.containsKey(password.charAt(i)))
                count.put(password.charAt(i), count.get(password.charAt(i)) + 1);
            else
                count.put(password.charAt(i), 1);
            }
        for (int i = 0; i < count.size(); i++) {
            if (count.get(password.charAt(i)) > highest_ch_count)
                    highest_ch_count = count.get(password.charAt(i));
        }
        float highest_percent = ((float) highest_ch_count / password.length()) * 100;
        float diff_char_percent = ((float) count.size() / password.length()) * 100;
        if (highest_percent < 45)
            singleCharScore = 20;
        else if (highest_percent >= 45 && highest_percent <= 55) {
            singleCharScore = 10;
        }else
            singleCharScore = 0;

        if (diff_char_percent > 55)
            multicharScore = 25;
        else {
            multicharScore= (int)diff_char_percent / 4;
        }
        int[] varianceScores = {singleCharScore, multicharScore};
        return varianceScores;
    }
    private static int[] getCharTypeScores(String password){
        int upper_count = 0, lower_count = 0, special_count = 0, num_count = 0, charTypeScore = 0;
        for (int i = 0; i < password.length(); i++) {
            if (Character.isUpperCase(password.charAt(i))) {
                if (upper_count > 1)
                    continue;
                charTypeScore += 2.5;
                upper_count++;
            } else if (Character.isLowerCase(password.charAt(i))) {
                if (lower_count > 1)
                    continue;
                charTypeScore += 2.5;
                lower_count++;
            } else if (Character.isDigit(password.charAt(i))) {
                if (num_count > 1)
                    continue;
                charTypeScore += 2.5;
                num_count++;
            } else {
                if (special_count > 1)
                    continue;
                charTypeScore += 2.5;
                special_count++;
            }
        }
        int [] charTypeScores = {charTypeScore, upper_count, lower_count, special_count, num_count};
        return charTypeScores;
    }
    private static int getCommonPasswordsScore(String password) throws Exception{
        BufferedReader bufReader = new BufferedReader(new FileReader("otherfiles/common_passwords.txt"));
        ArrayList<String> commonPasswords = new ArrayList<>();
        String line = bufReader.readLine();
        while (line != null) {
            commonPasswords.add(line);
            line = bufReader.readLine();
        }
        bufReader.close();
        if(commonPasswords.contains(password))
            return 0;
        else
            return 5;
    }   
    private static String getPasswordReccomendation(int lengthScore, int[] varianceScores, int[] charTypeScores){
        String reccomendation = "You can improve your password score using the following methods: ";
        if(lengthScore < 30)
            reccomendation +="<br>- Increasing the number of characters in your password. The ideal password length is 8 characters";
        if(varianceScores[0]<20)
            reccomendation +="<br>- Your password contains too much of the same character. Reduce the overuse of the same charater in your password";
        if(varianceScores[1]<25)
            reccomendation += "<br>- Increasing the variety of characters used";
        if(charTypeScores[1]<2)
            reccomendation += "<br>- Increasing number of upper case characters used";
        if(charTypeScores[2]<2)
            reccomendation += "<br>- Increasing number of lower case characters used";
        if(charTypeScores[3]<2)
            reccomendation += "<br>- Increasing number of special characters used";
        if(charTypeScores[4]<2)
            reccomendation += "<br>- Increasing number of numceric characters used";
        return reccomendation;
    }
    static String ConvertSectoDay(long n)
    {
        int years = (int) n/(24 * 3600 * 30 * 12);
        n = n % (24 * 3600 * 30 * 12);

        int months = (int) n/(24 * 3600 * 30);
        n = n % (24 * 3600 * 30);

        int day = (int) n / (24 * 3600);
        n = n % (24 * 3600);
        
        int hour = (int) n / 3600;
        n %= 3600;
        
        int minutes = (int) n / 60 ;
        n %= 60;
        
        int seconds = (int) n;
         
        String timeTakenToCrack = years + " years " + months+" months " + day + " " + "days " + hour+ " " + "hours " + minutes + " "
                           + "minutes " + seconds + " "
                           + "seconds ";

        if(years == 0 && months == 0 && day ==0)
            return timeTakenToCrack.substring(24, timeTakenToCrack.length());
        
        if(years == 0 && months == 0)
            return timeTakenToCrack.substring(17, timeTakenToCrack.length());

        return timeTakenToCrack;
    }
}