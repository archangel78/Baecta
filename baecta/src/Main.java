public class Main {
    public static void main(String args[]) throws Exception{
        ChromeInstallation.getInstallationData();
        System.out.println("\n[*] Chrome version: "+ChromeInstallation.getChromeVersion());
        
        if(Integer.parseInt(ChromeInstallation.getChromeVersion().substring(0, 2))>=80){
            System.out.println("[*] Chrome Version supported");
            ChromeDataCollector.getData();
            // testFunction();
            Analysis.checkMaliciousUrls();
            Analysis.checkPublicDataBreaches();
            Analysis.calculatePasswordStrength();
            DataWriter.generateHtmlReport();
        }else{
            System.out.println("[*] Chrome Version not supported");
        }
    }
    // public static void testFunction() throws Exception{
    //     Iterator<String> itr = UserData.getBrowserHistory().iterator();
    //     int threadQuantity = 4;
    //     int noThreads = UserData.getBrowserHistory().size()/threadQuantity;

    //     for(int i = 0 ; i < noThreads; i++){
    //         ArrayList<String> browserHistoryList = new ArrayList<String>();
    //         int temp = threadQuantity;
    //         while(itr.hasNext() && temp>0){
    //             browserHistoryList.add(itr.next());
    //             temp--;
    //         }
    //         if(i==noThreads-1)
    //             while(itr.hasNext())
    //                 browserHistoryList.add(itr.next());

    //         Thread malicioiusUrlCheckerThread = new Thread(new MalicioiusUrlCheckerRunnable(browserHistoryList));
    //         malicioiusUrlCheckerThread.start();
    //     }

    //     while(Analysis.maliciousUrlCounter < UserData.getBrowserHistory().size()){
    //         System.out.print("[*] Scanning Malicious URL's: " + Analysis.maliciousUrlCounter + "/" + UserData.getBrowserHistory().size() + "\r");
    //         Thread.sleep(10);
    //     }
    //     System.out.println("[*] Scanning Malicious URL's: " + Analysis.maliciousUrlCounter + "/" + UserData.getBrowserHistory().size());
    // }
}
