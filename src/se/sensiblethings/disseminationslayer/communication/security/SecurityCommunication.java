package se.sensiblethings.disseminationslayer.communication.security;

import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.disseminationcore.GetMessage;
import se.sensiblethings.disseminationlayer.disseminationcore.MessageListener;
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

/**
 * SecurityCommunication.java
 * 
 * This class extends the <code>Communication</code> class, to make itself to be one of the communication
 * that could be used. While it doesn't really implement its own communication, it uses the RUDP as its bottom
 * communication implementation. It also implements the <code>MessageListener</code> to acts as a middlerware to
 * exchange the certificates and session keys between each node.
 * 
 * <code>initCommunicationPort</code> specify the real communication(RUDP) port, default is 0;</p>
 * <code>initSecurityLevel</code>  specify the security level pre-defined in the configuration file 
 * (SecurityConfiguration.xml). The default setting is 2, which uses the RC4 as the symmetric encryption.</p> 
 * <code> uci </code> specify the itself uci. It should be pre-defined 
 * before the instantiation of the <code>SensibleThingsPlatform</code>.</p>
 * 
 * @author Hao
 *
 */
public class SecurityCommunication extends Communication implements MessageListener{
	
	private Communication communication = null;
	private SecurityConfiguration config = null;
	private SecurityManager securityManager = null;
	private MessageHandler messageHandler = null;
	
	private SensibleThingsNode localSensibleThingsNode = null;
	
	/**
	 * Initial communication port that RUDP used
	 */
	public static int initCommunicationPort = 0;
	
	/**
	 * Initial Security Level
	 */
	public static int initSecurityLevel = 2;

	/**
	 * itself UCI
	 */
	public static String uci = null;
	
	public SecurityCommunication(){
		this(initCommunicationPort);
	}
	
	public SecurityCommunication(int localPort){
		// set up the communication as RUDP
		RUDPCommunication.initCommunicationPort = initCommunicationPort;
		communication = new RUDPCommunication();
		// specify the local SensibleThingsNode
		this.localSensibleThingsNode = communication.getLocalSensibleThingsNode();
		// Combine self MessageLeisteners to RUDP's
		this.communication.setMessageListeners(super.getMessageListeners());
		
		//Register messages for security communication
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
		
		
		config = new SecurityConfiguration("config/SecurityConfiguration.xml", initSecurityLevel);
		securityManager = new SecurityManager(config);
		messageHandler = new MessageHandler(communication, securityManager, config);
		
		
		if(uci != null){
			messageHandler.securityRegister(uci);
		}else{
			System.err.println("[Security Communicaiton] UCI is null !");
		}
		
		// wait for the registration
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
	}
	
	/**
	 * Send out the messages with specified communication type
	 * @param message the message that will be sent
	 */
	@Override
	public void sendMessage(Message message)
			throws DestinationNotReachableException {
		// if this message will be sent to itself
		// it won't be encrypt
		if(message.getToNode().getAddress().equals(communication.getLocalSensibleThingsNode().getAddress())){
			communication.sendMessage(message);
		}else {
			// if this message is sent to bootstrap
			// then adds the toUci in this message
			if(message.toUci == null){
				message.toUci = messageHandler.getUciFromCache(message.getToNode().getAddress());
				
				// append the Uci to GetMessage
				if(message instanceof GetMessage){
					message.toUci = ((GetMessage) message).uci;
				}
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
