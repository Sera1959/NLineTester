import java.io.IOException;
import java.net.UnknownHostException;

public class Main {
    public static void main(String[] args) throws UnknownHostException, IOException {
    	
        String host = "server.myserver.us";
        int port = 9999;
        String user = "user";
        String password = "pass";
        byte[] configKey = new byte[]{ 01, 02, 03, 04, 05, 06, 07, 8, 9, 10, 11, 12, 13, 14 };

    	boolean valid = false;
    	
    	try {
			valid = new NewcamdConnector(host, port, user, password, configKey).TestNline();
		} catch (Exception e) {
			e.printStackTrace();
		}    	
    	
    	if (valid)
    		System.out.println("NLine is valid");
    	else
    		System.out.println("NLine is NOT valid");
    }
}
