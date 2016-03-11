import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.*;

public class NewcamdConnector {

  private String host, user, password;
  private int port;
  private byte[] configKey;
  private byte[] loginKey;
  private Socket socket;
  private DataInputStream is;
  private BufferedOutputStream os;

  public NewcamdConnector(String host, int port, String username, String psw, byte[] configKey) 
		  throws UnknownHostException, IOException {

    this.host = host;
    this.port = port;
    this.user = username;
    this.password = psw;
    this.configKey = configKey;
    
    socket = new Socket(this.host, this.port);
    is = new DataInputStream(socket.getInputStream());
    os = new BufferedOutputStream(socket.getOutputStream());
  }


  public boolean TestNline() throws Exception {
    try {
    	

	    byte[] fixedData = new byte[10];    	
    	
	  	byte[] helloBytes = new byte[14];
		is.readFully(helloBytes);
		
		loginKey = DESUtil.desKeySpread((DESUtil.xorKey(configKey, helloBytes)));
		
		
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    baos.write(user.getBytes());
	    baos.write(0);
	    baos.write(DESUtil.cryptPassword(password).getBytes());
	    baos.write(0);
	      
	    byte[] customData = baos.toByteArray();
		    
	    fixedData[2] = 00;
	    fixedData[3] = 00;
		
	    byte[] buffer = new byte[13 + customData.length];
		
		
	    System.arraycopy(fixedData, 0, buffer, 0, 10);
	    buffer[10] = (byte)0xE0;
	    buffer[11] = (byte)(customData.length >> 8);
	    buffer[11] |= 0;
	    buffer[12] = (byte)(customData.length & 0xFF);
	    System.arraycopy(customData, 0, buffer, 13, customData.length);
	    
	    
	    byte[] encrypted = DESUtil.desEncrypt(buffer, buffer.length, loginKey, 240);

        os.write(encrypted);
        os.flush();
        
        int a = is.read();
	    	        

	    byte[] data = new byte[100];
      	is.readFully(data);
	    
      	byte[] decrypted = DESUtil.desDecrypt(data, data.length, loginKey);
      	
      	
		
		socket.close();
		is.close();
		os.close();
		return true;
			
    } catch(Exception e) {
    	System.out.println(e.toString());
    	e.printStackTrace();
    }
	socket.close();
	is.close();
	os.close();
    return false;
  }
}
