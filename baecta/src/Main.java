public class Main {
    public static void main(String args[]){
        ChromeInstallation.getInstallationData();
        System.out.println("\n[*] Chrome version: "+ChromeInstallation.getChromeVersion());
        
        if(Integer.parseInt(ChromeInstallation.getChromeVersion().substring(0, 2))>=80){
            System.out.println("[*] Chrome Version supported");
            ChromeDataCollector.getData();
            Analysis.checkMaliciousUrls();
            Analysis.checkPublicDataBreaches();
            PasswordAnalysis.calculatePasswordStrength();
            DataWriter.generateHtmlReport();
        }else{
            System.out.println("[*] Chrome Version not supported");
        }
    }
}
