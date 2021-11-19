import java.util.*;

public class UserData {
    private static Set<String> browserHistory = new HashSet<String>(); 
    private static List<Credential> credentials = new ArrayList<Credential>();

    public static void setBrowserHistory(Set<String> bHistory){
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
