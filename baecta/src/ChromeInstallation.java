import java.util.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.json.simple.JSONObject;

class ChromeInstallation{

	private static final String chromeInstallationPath = "C:\\Users\\"+System.getProperty("user.name")+"\\AppData\\Local\\Google\\Chrome\\User Data";
	private static final String localStatePath = "C:\\Users\\"+System.getProperty("user.name")+"\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
	private static String historyPath;
	private static String loginDataPath;
	private static String chromeMasterKey;
	private static String chromeVersion;
	private static String profileName;

	public static void getInstallationData(){
			getInstallationPaths();
			getLocalStateData();
	}

	private static void getInstallationPaths(){
		File chrome_directory = new File(chromeInstallationPath);
		if(chrome_directory.exists()){
			String[] directory_list = chrome_directory.list(); 
			List<String> profiles = new ArrayList<String>();
			System.out.println("[*] Google Chrome installation successfully detected");

			for(int i = 0; i < directory_list.length; i++){
				if(directory_list[i].equals("Default") || directory_list[i].contains("Profile")){
					profiles.add(directory_list[i]);
				}
			}
			if(profiles.size()>1){
				System.out.println("[*] Multiple profiles were found in your system: ");
				for(int i = 0; i < profiles.size(); i++)
					System.out.print(i+1+". "+profiles.get(i)+"\t");
				System.out.print("\nKindly select a profile number for analysis: ");

				Scanner scanner = new Scanner(System.in);
				int profile_no = scanner.nextInt();
				profileName = profiles.get(profile_no-1);
				scanner.close();
				if(profile_no>0 && profile_no<=profiles.size()){
					historyPath = chromeInstallationPath + "\\" + profileName + "\\History";
					loginDataPath = chromeInstallationPath + "\\" + profileName + "\\Login Data";
				}else{
					System.out.println("[*] Incorrect profile selected");
					System.exit(0);
				}
			}else{
				System.out.println("[*] Chrome profile \""+profiles.get(0)+"\" was succesfully detected");
				historyPath = chromeInstallationPath + "\\" + profiles.get(0) + "\\History";
				loginDataPath = chromeInstallationPath + "\\" + profiles.get(0) + "\\Login Data";
			}
		}else{
			System.out.println("[*] Google Chrome is not installed on your system");
			System.exit(0);
		}
	}
	private static void getLocalStateData(){
		JSONParser jsonParser = new JSONParser();
		JSONObject rootObject;
		try{
			rootObject = (JSONObject) jsonParser.parse(new FileReader(localStatePath));
			JSONObject user_metrics = (JSONObject) rootObject.get("user_experience_metrics");
			JSONObject stability = (JSONObject) user_metrics.get("stability");
			chromeVersion = (String) stability.get("stats_version");

			JSONObject os_crypt = (JSONObject) rootObject.get("os_crypt");
			chromeMasterKey = (String) os_crypt.get("encrypted_key");
		}catch(FileNotFoundException e){
			System.out.println("[*] Chrome Installation Files missing. Try reinstalling chrome");
			System.exit(0);
		}catch(IOException e){
			System.out.println("[*] IOException occurred while reading chrome installation files");
			System.exit(0);
		} catch (ParseException e) {
			System.out.println("[*] ParseException occurred while parsing local state json file");
			System.exit(0);
		}
		
	}
	public static String getHistoryPath(){
		return historyPath;
	}
	public static String getLoginDataPath(){
		return loginDataPath;
	}
	public static String getChromeMasterKey(){
		return chromeMasterKey;
	}
	public static String getChromeVersion(){
		return chromeVersion;
	}
	public static String getProfileName(){
		return profileName;
	}
}
