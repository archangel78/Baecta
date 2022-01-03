import java.util.*;

public class UserData {
    static HashSet<String> browserHistory = new HashSet<String>(); 
    private static List<Credential> credentials = new ArrayList<Credential>();

    public static void setBrowserHistory(HashSet<String> bHistory){
        browserHistory = bHistory;
    }
    public static void setCredentials(List<Credential> creds){
        credentials = creds;
    }
    public static Set<String> getBrowserHistory(){
        return browserHistory;
    }
    public static List<Credential> getCredentials(){
        return credentials;
    }
}
