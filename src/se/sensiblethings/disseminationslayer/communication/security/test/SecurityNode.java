package se.sensiblethings.disseminationslayer.communication.security.test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;

import se.sensiblethings.addinlayer.extensions.security.SecurityExtension;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.LookupService;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.disseminationslayer.communication.security.SecurityCommunication;
import se.sensiblethings.interfacelayer.SensibleThingsListener;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.interfacelayer.SensibleThingsPlatform;

public class SecurityNode implements SensibleThingsListener, Runnable{
	
	SensibleThingsPlatform platform = null;
	SecurityExtension secureExt = null;

	final static String myUci = "sensiblethings@miun.se/Node#11";
	
	
	public static void main(String arg[]){
		SecurityNode application = new SecurityNode();
		application.run();
	}

	public SecurityNode(){
		
		//Create the platform itself with a SensibleThingsListener
		//KelipsLookup.bootstrap = true;
		
		KelipsLookup.bootstrapIp = getLocalHostAddress();
		KelipsLookup.bootstrap = false;
		
		SecurityCommunication.initCommunicationPort = 49860;
		SecurityCommunication.uci = myUci;
		platform = new SensibleThingsPlatform(LookupService.KELIPS, Communication.SECURITY_COM, this);
		
	}
	
	@Override
	public void run(){
    	try {
    		System.out.println("[Node#11 Node] booted! ");
    		
    		platform.register(myUci);
    		
    		platform.resolve("sensiblethings@miun.se/bootstrap");
    		
    		KelipsLookup.bootstrap = true;
    		
	        System.out.println("[Node#11 Node] Press any key to shut down");
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
		
		
	}

	@Override
	public void resolveResponse(String uci, SensibleThingsNode node) {
		System.out.println("[Node#11 : ResolveResponse] " + uci + ": " + node);
		
		platform.set(uci, "Hello world", node);
	}

	@Override
	public void getEvent(SensibleThingsNode source, String uci) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEvent(SensibleThingsNode fromNode, String uci, String value) {
		// TODO Auto-generated method stub
		
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
