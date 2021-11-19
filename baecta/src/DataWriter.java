import java.nio.file.Path;
import java.nio.file.Files;
import java.io.FileReader;
import java.io.BufferedReader;
import org.json.simple.JSONObject;
import org.json.simple.JSONArray;

public class DataWriter {
    private static String credentialTable = "", breachedTable = "", maliciousURLTable = "";

    public static void generateHtmlReport() throws Exception{
        String templateHtmlText="";

        BufferedReader bufReader = new BufferedReader(new FileReader("otherfiles/template.html"));
        String line = bufReader.readLine();
        while (line != null) {
            templateHtmlText+=line;
            line = bufReader.readLine();
        }
        bufReader.close();

        templateHtmlText = templateHtmlText.replace("credential_table", credentialTable);
        templateHtmlText = templateHtmlText.replace("breached_table", breachedTable);
        templateHtmlText = templateHtmlText.replace("malicious_table", maliciousURLTable);
        templateHtmlText = templateHtmlText.replace("chrome_version", ChromeInstallation.getChromeVersion());
        templateHtmlText = templateHtmlText.replace("profile", ChromeInstallation.getProfileName());

        Path reportFilePath = Path.of("otherfiles/report.html");
        Files.writeString(reportFilePath,templateHtmlText);

        System.out.println("[*] Opening report in browser");
        Runtime.getRuntime().exec("cmd /c start otherfiles/report.html");
    }

    public static void addMaliciousUrl(JSONObject root, String current_url){
        if((Boolean)root.get("success")==true){
            String spamming = root.get("spamming").toString();
            String malware = root.get("malware").toString();
            String phishing = root.get("phishing").toString();
            String suspicious = root.get("suspicious").toString();
            String risk_score = root.get("risk_score").toString();

            if(spamming.equals("true") || malware.equals("true") || phishing.equals("true") || suspicious.equals("true")){
                
                maliciousURLTable += "<tr>";
                maliciousURLTable += "<td>"+current_url+"</td>";
                maliciousURLTable += "<td>"+risk_score+"</td>";
                maliciousURLTable += "<td>"+phishing+"</td>";
                maliciousURLTable += "<td>"+malware+"</td>";
                maliciousURLTable += "<td>"+spamming+"</td>";
                maliciousURLTable += "<td>"+suspicious+"</td>";
                maliciousURLTable += "</tr>";
            }
        }
    }
    public static void addBreachedWebsite(JSONArray root, String email){
        for(int i = 0; i < root.size(); i++){
            JSONObject jsonObject = (JSONObject)root.get(i);
            breachedTable += "<tr>";
            breachedTable += "<td>"+jsonObject.get("Name")+"</td>";
            breachedTable += "<td>"+email+"</td>";
            breachedTable += "</tr>";
        }
    }
    public static void addCredential(String username, String password, int password_score, String password_advice, String time_to_crack, String url){
        credentialTable += "<tr>";
        credentialTable += "<td>" + url  + "</td>";
        credentialTable += "<td>" + username + "</td>";
        credentialTable += "<td>" + password + "</td>";
        credentialTable += "<td>" + password_score + "</td>";
        credentialTable += "<td>" + password_advice + "</td>";
        credentialTable += "<td>" + time_to_crack + "</td>";
        credentialTable += "</tr>";

    }
}
