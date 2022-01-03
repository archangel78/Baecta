import java.util.*;
import java.net.URL;
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

    public static void checkMaliciousUrls() {
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
            try{            
                Thread.sleep(10);
            }catch(InterruptedException e){
                System.out.println("[*] Sleep interrupted");
            }
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
            System.exit(0);
        }
    }

    static Boolean checkEmail(String username) {
        String regex = "^(.+)@(.+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(username);
        return matcher.matches();
    }

}