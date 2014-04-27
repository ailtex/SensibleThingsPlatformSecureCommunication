package se.sensiblethings.disseminationslayer.communication.security;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.disseminationcore.MessageListener;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.disseminationslayer.communication.security.configuration.SecurityConfiguration;
import se.sensiblethings.disseminationslayer.communication.security.messagehandler.MessageHandler;
import se.sensiblethings.interfacelayer.SensibleThingsNode;
import se.sensiblethings.disseminationslayer.communication.security.messagehandler.SecurityManager;
import se.sensiblethings.disseminationslayer.communication.security.messages.CertificateAcceptedResponseMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.CertificateExchangeMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.CertificateExchangeResponseMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.CertificateRequestMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.CertificateResponseMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.CommunicationShiftMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.RegistrationRequestMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.RegistrationResponseMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.SecureMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.SessionKeyExchangeMessage;
import se.sensiblethings.disseminationslayer.communication.security.messages.SessionKeyResponseMessage;

public class SecurityCommunication extends Communication implements MessageListener{
	
	private Communication communication = null;
	private SecurityConfiguration config = null;
	private SecurityManager securityManager = null;
	private MessageHandler messageHandler = null;
	
	private int communicationPort = 0;
	private SensibleThingsNode localSensibleThingsNode = null;
	
	public static int initCommunicationPort = 0;
	
	public static String uci = null;
	
	public SecurityCommunication(){
		this(initCommunicationPort);
	}
	
	public SecurityCommunication(int localPort){
		// set up the communication with rudp
		RUDPCommunication.initCommunicationPort = initCommunicationPort;
		communication = new RUDPCommunication();
		this.localSensibleThingsNode = communication.getLocalSensibleThingsNode();
		
		this.communication.setMessageListeners(super.getMessageListeners());
		
		//Register our own message types in the post office
		communication.registerMessageListener(CommunicationShiftMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationRequestMessage.class.getName(), this);
		communication.registerMessageListener(RegistrationResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateRequestMessage.class.getName(), this);
		communication.registerMessageListener(CertificateResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateAcceptedResponseMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyExchangeMessage.class.getName(), this);
		communication.registerMessageListener(SessionKeyResponseMessage.class.getName(), this);
		communication.registerMessageListener(CertificateExchangeMessage.class.getName(), this);
		communication.registerMessageListener(CertificateExchangeResponseMessage.class.getName(), this);
		communication.registerMessageListener(SecureMessage.class.getName(), this);
		
		
		config = new SecurityConfiguration("config/SecurityConfiguration.xml", 2);
		securityManager = new SecurityManager(config);
		messageHandler = new MessageHandler(communication, securityManager, config);
		
		
		if(uci != null){
			messageHandler.securityRegister(uci);
		}else{
			System.err.println("[Security Communicaiton] UCI is null !");
		}
		
		
		// wait for the registration
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		
	}
	
	@Override
	public void sendMessage(Message message)
			throws DestinationNotReachableException {
//		System.out.println("[Send Message] : " + message);
		
		// if this message will be sent to itself
		// it won't be encrypt
		if(message.getToNode().getAddress().equals(communication.getLocalSensibleThingsNode().getAddress())){
			communication.sendMessage(message);
		}else {
			// if this message is sent to bootstrap
			// then adds the toUci in this message
			
			if(message.toUci == null){
				String toUci = messageHandler.getUciFromCache(message.getToNode().getAddress());
				message.toUci = toUci;
//				System.out.println("[Append UCI] " + message.toUci + " --> " + message);
			}
			
			messageHandler.sendSecureMassage(message, message.toUci, message.getToNode());
		}
		
	}

	@Override
	public void shutdown() {
		
	}

	@Override
	public SensibleThingsNode getLocalSensibleThingsNode() {
		return localSensibleThingsNode;
	}

	@Override
	public void handleMessage(Message message) {
		if(message instanceof CommunicationShiftMessage) {
			CommunicationShiftMessage scm = (CommunicationShiftMessage)message;
			messageHandler.handleCommunicationShiftMessage(scm);
			
		}else if(message instanceof RegistrationRequestMessage){
			RegistrationRequestMessage registrationRequestMessage = (RegistrationRequestMessage) message;
			messageHandler.handleRegistrationRequestMessage(registrationRequestMessage);
			
		}else if(message instanceof RegistrationResponseMessage){
			RegistrationResponseMessage rrm = (RegistrationResponseMessage) message;
			messageHandler.handleRegistrationResponseMessage(rrm);
			
		}else if(message instanceof CertificateRequestMessage){
			CertificateRequestMessage crm = (CertificateRequestMessage)message;
			messageHandler.handleCertificateRequestMessage(crm);

		}else if(message instanceof CertificateResponseMessage){
			CertificateResponseMessage crm = (CertificateResponseMessage)message;
			messageHandler.handleCertificateResponseMessage(crm);
			
		}else if(message instanceof CertificateAcceptedResponseMessage){
			CertificateAcceptedResponseMessage carm = (CertificateAcceptedResponseMessage)message;
			messageHandler.handleCertificateAcceptedResponseMessage(carm);
			
		}else if(message instanceof SessionKeyExchangeMessage){
			SessionKeyExchangeMessage skxm = (SessionKeyExchangeMessage)message;	
			messageHandler.handleSessionKeyExchangeMessage(skxm);
			
		}else if(message instanceof SessionKeyResponseMessage){
			SessionKeyResponseMessage skrm = (SessionKeyResponseMessage)message;
			messageHandler.handleSessionKeyResponseMessage(skrm);
				
		}else if(message instanceof CertificateExchangeMessage){
			CertificateExchangeMessage cxm = (CertificateExchangeMessage)message;
			messageHandler.handleCertificateExchangeMessage(cxm);
			
		}else if(message instanceof CertificateExchangeResponseMessage){
			CertificateExchangeResponseMessage cxrm = (CertificateExchangeResponseMessage)message;
			messageHandler.handleCertificateExchangeResponseMessage(cxrm);
			
		}else if(message instanceof SecureMessage){
			SecureMessage sm = (SecureMessage)message;
			
			Message msg = messageHandler.handleSecureMessage(sm);
			
			//Send the message to the "PostOffice"
			dispatchMessageToPostOffice(msg);
			
		}
		
	}
	
}
