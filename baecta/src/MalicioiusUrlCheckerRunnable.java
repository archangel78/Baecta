import java.util.*;
import org.json.simple.parser.JSONParser;
import org.json.simple.JSONObject;

public class MalicioiusUrlCheckerRunnable implements Runnable{
    
    private static ArrayList<String> browserHistory = new ArrayList<String>();
    
    public MalicioiusUrlCheckerRunnable(ArrayList<String> bHistory){
        browserHistory = bHistory;
    }
    @Override
    public void run() {
        try{
            Iterator<String> itr = browserHistory.iterator();
            while(itr.hasNext()){
                String current_url = itr.next();
                String output = Analysis.getApiConnection(Analysis.getIpQualityApiEndpoint() + current_url, "", "");

                if (output != null) {
                    JSONParser parser = new JSONParser();
                    JSONObject root = (JSONObject) parser.parse(output);
                    DataWriter.addMaliciousUrl(root, current_url);
                }
                Analysis.maliciousUrlCounter++;
            }
        }catch(Exception e){
            System.out.println("[*] Exception occurred: "+e+"\n[*] Terminating");
			System.exit(0);
        }
    }
    
}
