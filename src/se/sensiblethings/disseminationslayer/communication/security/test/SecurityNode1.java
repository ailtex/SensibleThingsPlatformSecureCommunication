package se.sensiblethings.disseminationslayer.communication.security.test;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;

import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.disseminationslayer.communication.security.SecurityCommunication;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityNode1 implements SensibleThingsListener, Runnable{
	
	SensibleThingsPlatform platform = null;

	final static String myUci = "sensiblethings@miun.se/Node1";
	
	
	public static void main(String arg[]){
		SecurityNode1 application = new SecurityNode1();
		application.run();
	}

	public SecurityNode1(){
		
		//Create the platform itself with a SensibleThingsListener
		//KelipsLookup.bootstrap = true;
		
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		KelipsLookup.bootstrap = false;
		
		SecurityCommunication.initCommunicationPort = 0;
		SecurityCommunication.uci = myUci;
		platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SECURITY_COM, this);
		
	}
	
	@Override
	public void run(){
    	try {
    		System.out.println("[Node#1 Node] booted! ");
    		
    		platform.register(myUci);
    		
    		platform.resolve("sensiblethings@miun.se/Node2");
    		
			// when jvm exist, delete the keyStore file
			File keystore = new File("resources/sensiblethings@miun.se_Node1_KeyStore.db");
			keystore.deleteOnExit();
    		
	        System.out.println("[Node#1 Node] Press any key to shut down");
	        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));    	
			in.readLine();
			
			//Shutdown all background tasks
			platform.shutdown();
			
		} catch (Exception e) {
			e.printStackTrace();
		}    	
    }

	public void shutdown(){
		platform.shutdown();
	}
	
	@Override
	public void getResponse(String uci, String value,
			SensibleThingsNode fromNode) {
		System.out.println("[Node#1 : Get Response] " + uci + ": " + fromNode + ": " + value);
		
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[Node#1 : ResolveResponse] " + uci + ": " + node);
		
		platform.get(uci, node);
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		System.out.println("[Node#1 : GetEvent] " + uci + ": " + source);
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		System.out.println("[Node#1 : SetEvent] " + uci + ": " + value + " : " + fromNode);
		
	}
	
	/*
	 * find the local host IP address
	 */
    private String getLocalHostAddress() {
    	InetAddress address = null;
    	
    	try {
    		address = InetAddress.getLocalHost();

		} catch (UnknownHostException e) {
			System.out.println("Could not find this computer's address.");
		}
    	
		return address.getHostAddress();
	}
    
    private String generateMessage(int length){
    	Random random = new Random(System.currentTimeMillis());
    	byte[] message = new byte[length];
    	random.nextBytes(message);
    	
    	return Base64.toBase64String(message);
    }
}
