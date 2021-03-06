package se.sensiblethings.disseminationslayer.communication.security.messagehandler;

import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Vector;

import org.apache.commons.lang.SerializationUtils;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import se.sensiblethings.disseminationlayer.communication.Communication;
import se.sensiblethings.disseminationlayer.communication.DestinationNotReachableException;
import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.disseminationlayer.communication.rudp.RUDPCommunication;
import se.sensiblethings.disseminationlayer.communication.ssl.SslCommunication;
import se.sensiblethings.disseminationlayer.lookupservice.kelips.KelipsLookup;
import se.sensiblethings.disseminationslayer.communication.security.configuration.SecurityConfiguration;
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
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.CertificateExchangePayload;
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.CertificatePayload;
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.CertificateResponsePayload;
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.RegistrationPayload;
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.ResponsePayload;
import se.sensiblethings.disseminationslayer.communication.security.messages.payload.SecretKeyPayload;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

/**
 * MessageHandler.java
 * 
 * This class handles all communication messages in this protocol.
 * 
 * @author Hao
 *
 */
public class MessageHandler {

	private Communication communication = null;
	private SecurityManager securityManager = null;
	private SecurityConfiguration config = null;
	// Temporarily store the up going secure messages
	private Map<String, Vector<SecureMessage>> postOffice = null;
	// cache the UCI corresponding to net address
	private Map<String, String> uciCache = null;
	
	/**
	 * The password that protect the key and key store safe
	 */
	public static final char[] password = "password".toCharArray();
	
	/**
	 * Initialization of the message handler
	 * @param communication the communication that bottom level used
	 * @param securityManager the manager provides all kinds of security operations
	 * @param config the security configuration
	 */
	public MessageHandler(Communication communication, 
			SecurityManager securityManager, SecurityConfiguration config){

		this.communication = communication;
		
		this.securityManager = securityManager;
		this.config = config;
		
		postOffice = new HashMap<String, Vector<SecureMessage>>();
		uciCache = new HashMap<String, String>();
	}
	
	/**
	 * Set the configuration
	 * @param config the security configuration containing kinds of parameters
	 */
	public void setSecuiryConfiguraton(SecurityConfiguration config){
		this.config = config;
	}
	
	/**
	 * Using the itself UCI, it first initialize the key store with generating its key pair 
	 * and self signed certificate. Then it check whether it has the signed certificate, it will
	 * send the registration request to the bootstrap if not.
	 * 
	 * @param uci Itself UCI
	 */
	public void securityRegister(String uci){

		// Initialize the key Store, with generating its key pair and self signed certificate
		securityManager.initializeKeyStore(uci, password, password);
		
		// Check if it's has the signed certificate
		// if it's not, it should connect to the Bootstrap and get the signed
		// certificate
	
		if (!securityManager.isRegisted(uci, config.getBootstrapUci()) && !uci.equals(config.getBootstrapUci()) ) {
				
			SensibleThingsNode bootstrapNode = new SensibleThingsNode(KelipsLookup.bootstrapIp, 
					Integer.valueOf(config.getBootstrapPort()));
			
			addToUciCache(bootstrapNode.getAddress(), config.getBootstrapUci());
//			createSslConnection(config.getBootstrapUci(),bootstrapNode);

			register(config.getBootstrapUci(), bootstrapNode);
		}

	}
	
	
	/**
	 * Create a SSL connection with bootstrap node</p>
	 * 
	 * (1.1) C->B: Create a SSL Session with B
	 * 
	 * @param uci the UCI who own the bootstrap node
	 * @param node the node that SSL connection is established with 
	 */
	public void createSslConnection(String uci, SensibleThingsNode node){
		//Send out the SslConnectionRequestMessage Message
		CommunicationShiftMessage message = new CommunicationShiftMessage(uci, securityManager.getMyUci(), 
				node, communication.getLocalSensibleThingsNode());
		
		message.setSignal("SSL");
		// this message may not be secure, as if some one can hijack it
	    // if the bootstrap node can set up several different communications simultaneously
	    // the request node can just change itself communication type
		
		sendMessage(message);
		
		transformCommunication("SSL");
		
	}
	
	/**
	 * The system changes the communication type when it received corresponding signal
	 * 
	 * @param csm the communication shift message
	 */
	public void handleCommunicationShiftMessage(CommunicationShiftMessage csm) {
		if(csm.getSignal() != null){
			transformCommunication(csm.getSignal());
		}
	
	}
	
	/**
	 * Register the self uci to bootstrap node</p>
	 *  
	 * (1.2) C->B: IDC || Request || TS1
	 *  
	 * @param toUci the boostrap's uci
	 * @param node the bootstrap node
	 * @param fromUci itself uci that will be registered
	 */
	private void register(String toUci, SensibleThingsNode node){
//		System.out.println("[Register] " + securityManager.getMyUci() + " --> " + toUci);
		
		RegistrationRequestMessage message = new RegistrationRequestMessage(toUci, securityManager.getMyUci(), 
				node, communication.getLocalSensibleThingsNode());
		
		// set the payload
		RegistrationPayload payload = new RegistrationPayload(securityManager.getMyUci(), toUci);
		payload.setTimeStamp(System.currentTimeMillis());
		byte[] payloadInBytes= SerializationUtils.serialize(payload);
				
		message.setPayload(payloadInBytes);
		message.setSignature(null);
		
		// store the local registration Request Time
		securityManager.addToNoncePool("RegistrationRequest", payloadInBytes);

		sendMessage(message);
	}
	
	/**
	 * Handle Registration Request Message, sends back an registration response message </p>
	 * 
	 * (1.3) B->C: IDB || PUB || E(PRB, [IDC || Request || TS1])
	 * 
	 * @param rrm the registration request message
	 */
	public void handleRegistrationRequestMessage(
			RegistrationRequestMessage rrm) {
		
//		System.out.println("[Handle Registration Request Message] " + " from "+ rrm.fromUci);
		
		RegistrationResponseMessage registrationResponseMessage = 
				new RegistrationResponseMessage(rrm.fromUci, securityManager.getMyUci(), 
						rrm.getFromNode(),communication.getLocalSensibleThingsNode());
				
		// set the Root certificate from Bootstrap and send it to the applicant
		registrationResponseMessage.setCertificate(securityManager.getCertificate());
		
		// set the signature algorithm of the message
		registrationResponseMessage.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// signed the request message
		byte[] signature = securityManager.signMessage(rrm.getPayload(), config.getSignatureAlgorithm(), password);
		
		// set the signature
		registrationResponseMessage.setSignature(signature);
		
		// send out the message
		sendMessage(registrationResponseMessage);
	}
	
	/**
	 * Handle Registration Response Message </p>
	 * 
	 * (1.4) C->B: E(PUB, [IDC || N1 ]) || CERTc (IDC || PUC || E(PRC, H(IDC || PUC)) ) 
	 * 
	 * @param rrm the registration response message
	 */
	public void handleRegistrationResponseMessage(
			RegistrationResponseMessage rrm) {
//		System.out.println("[Handle Registration Response Message ]" + " from " + rrm.fromUci);
		
	  	// verify the signature with the given certificate from bootstrap
		if(securityManager.verifySignature((byte[])securityManager.getFromNoncePool("RegistrationRequest"), 
				rrm.getSignature(), rrm.getCertificate(), rrm.getSignatureAlgorithm())){
			
			// remove the registration request from the nonce pool
			securityManager.removeFromNoncePool("RegistrationRequest");
			
			// store the bootstrap's root certificate(X509V1 version)
			securityManager.storeCertificate(rrm.fromUci, rrm.getCertificate(), "password".toCharArray());
			
			// the request is valid
			// send the certificate request message with ID, CSR, nonce 
			CertificateRequestMessage crm = 
					new CertificateRequestMessage(config.getBootstrapUci(),
							securityManager.getMyUci(), rrm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			//generate an certificate signing request
			PKCS10CertificationRequest certRequest = 
					securityManager.getCertificateSigingRequest(securityManager.getMyUci(), password);
			
			crm.setCertRequest(certRequest);
			
			// set the nonce
			int nonce = new Random().nextInt();
			crm.setNonce(securityManager.asymmetricEncryptMessage(
					rrm.fromUci, String.valueOf(nonce).getBytes(), config.getAsymmetricAlgorithm()));
			
			// store the nonce into the data pool, corresponding the bootstrap's uci
			securityManager.addToNoncePool(rrm.fromUci, nonce);
			
			
			// set the fromUci
			crm.setUci(securityManager.asymmetricEncryptMessage(
					rrm.fromUci, securityManager.getMyUci().getBytes(), config.getAsymmetricAlgorithm()));
			
			sendMessage(crm);
			
		}else{
			System.err.println("[Error] Fake signature");
		}
	}

	/**
	 * Handle Certificate Request Message</p>
	 * 
	 * (1.5) B->C: E(PUC, K ) || E(K, [Certification || N1 || N2])
	 * 
	 * @param crm certificate request message
	 */
	public void handleCertificateRequestMessage(CertificateRequestMessage crm) {
//		System.out.println("[Handle Certificate Request Message ]" + " from " + crm.fromUci);
			
		// Get the certificate signing request
		PKCS10CertificationRequest certRequest = crm.getCertRequest();
		
		// Get the uci
		String uci = new String(securityManager.asymmetricDecryptMessage(crm.getUci(), config.getAsymmetricAlgorithm(), password));
		
		// Get the nonce
		int nonce = Integer.valueOf(new String(securityManager.asymmetricDecryptMessage(crm.getNonce(), config.getAsymmetricAlgorithm(), password))) ;
		
		// varify the certificate signing request
		if(securityManager.isCeritificateSigningRequestValid(certRequest, uci)){
			Certificate[] certs = (Certificate[]) securityManager.signCertificateSigningRequest(certRequest, crm.fromUci, password,password);
			
			
			// generate the session key and  store it locally
			securityManager.generateSymmetricSecurityKey(crm.fromUci, config.getSymmetricAlgorithm(), config.getSymmetricKeyLength(), password, password);
			
			CertificateResponseMessage certRespMesg = new CertificateResponseMessage(crm.fromUci, securityManager.getMyUci(),
															crm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			certRespMesg.setEncryptSecretKey(securityManager.asymmetricEncryptMessage(
								crm.fromUci, 
								securityManager.getSecretKey(crm.fromUci, password).getEncoded(),
								config.getAsymmetricAlgorithm()));
			
			CertificateResponsePayload responsePayload = 
					new CertificateResponsePayload(securityManager.getMyUci(), crm.fromUci);
			
			// set the nonces
			responsePayload.setToNonce(nonce);
			
			int fromNonce = new Random().nextInt();
			responsePayload.setFromNonce(fromNonce);
			// store into the data pool
			securityManager.addToNoncePool(crm.fromUci, fromNonce);
			
			// set the certificate chain, which contains the signed certificate and root certificate of Bootstrap
			responsePayload.setCertChain(certs);
			
			byte[] encryptPayload = securityManager.symmetricEncryptMessage(crm.fromUci, 
					SerializationUtils.serialize(responsePayload), config.getSymmetricMode(), password);
			
			byte[] iv = securityManager.getIVparameter();
			if(iv != null){
				certRespMesg.setIv(securityManager.symmetricEncryptIVParameter(crm.fromUci, iv, password));
			}
			
			certRespMesg.setPayload(encryptPayload);
			
			sendMessage(certRespMesg);
			
		}else{
			System.err.println("[Handle Certificate Request Message] " + "Ceritificate Signing Request Error");
		}
		
	}
	
	/**
	 * Handle Certificate Response Message </p>
	 * 
	 * (1.6) C->B : E(K, N2)
	 * 
	 * @param crm the certificate response message
	 */
	public void handleCertificateResponseMessage(
			CertificateResponseMessage crm) {
//		System.out.println("[Handle Certificate Response Message ]" + " from " + crm.fromUci + " to " + crm.toUci);
		
		byte[] encryptSecretKey = crm.getEncryptSecretKey();
		// decrypt the secret key
		byte[] secretKey = securityManager.asymmetricDecryptMessage(encryptSecretKey, 
				config.getAsymmetricAlgorithm(), password);
		
		// decrypt the payload
		byte[] payload = securityManager.decryptPayload(secretKey,  crm.getIv(),
				crm.getPayload(), config.getSymmetricMode());
		
		// deserialize
		CertificateResponsePayload responsePayload = (CertificateResponsePayload)
				SerializationUtils.deserialize(payload);
		
		// varify the nonce
		if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(crm.fromUci)){
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool(crm.fromUci);
			
			// store the secret key
			securityManager.storeSecretKey(crm.fromUci, secretKey, config.getSymmetricAlgorithm(), password ,password);
			
			securityManager.storeCertificateChain(securityManager.getMyUci(), responsePayload.getCertChain(), password, password);
			
			//System.out.println("[Handle Certificate Response Message]"+ responsePayload.getCertChain()[0]);
			
			//send back CertificateAcceptedResponseMessage
			CertificateAcceptedResponseMessage carm = 
					new CertificateAcceptedResponseMessage(crm.fromUci, securityManager.getMyUci(), 
							crm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			int nonce =  responsePayload.getFromNonce();
			
			carm.setPayload(securityManager.symmetricEncryptMessage(crm.fromUci, 
					String.valueOf(nonce).getBytes(), config.getSymmetricMode(), password));
			
			byte[] ivParameter = securityManager.getIVparameter();
			if(ivParameter != null){
				carm.setIv(securityManager.symmetricEncryptIVParameter(crm.fromUci, ivParameter, password));
			}
			
			sendMessage(carm);
			
//			// send the communication shift message 
//			CommunicationShiftMessage csm = new CommunicationShiftMessage(crm.fromUci, securityManager.getMyUci(), 
//					crm.getFromNode(), communication.getLocalSensibleThingsNode());
//			csm.setSignal("RUDP");
//			
//			sendMessage(csm);
//			
//			transformCommunication(csm.getSignal());
//			
			System.out.println("Registration finished!");
			
		}else{
			System.err.println("[Hanle Certificate Response Message] Wrong Nonce !");
		}
	}
	
	/**
	 * Handle the certificate accepted response message
	 * 
	 * @param carm the certificate accepted response message
	 */
	public void handleCertificateAcceptedResponseMessage(
			CertificateAcceptedResponseMessage carm) {
		
//		System.out.println("[Handle Certificate Accepted Response Message ]" + " from " + carm.fromUci);
		
		byte[] payload = securityManager.decryptPayload(carm.fromUci, carm.getIv(), 
				carm.getPayload(), config.getSymmetricMode(), password);
				
		// convert byte array to integer
		int nonce = Integer.valueOf(new String(payload));
		
		if(nonce == (Integer)securityManager.getFromNoncePool(carm.fromUci)){
			System.out.println("[Handle Certificate Accepted Response Message] Certificate has been safely transmitted!");
			
			// remove the nonce from the data pool
			securityManager.removeFromNoncePool(carm.fromUci);
		}else{
			System.out.println("[Handle Certificate Accepted Response Message] Error!");
		}
		
	}
	
	
	/**
	 * Send encrypt message</p>
	 * 
	 * (2.1) if (IDD, KS, Lifetime) exist, and Lifetime is valid
	 *       C->D: E(KS, IDC || M || E(PRC, [H(M)] ) )
	 * 
	 * @param message the up going message
	 * @param toUci the UCI of the receiver
	 * @param toNode the node of the receiver
	 */
	public void sendSecureMassage(Message message, String toUci, SensibleThingsNode toNode){   
		
		// create the secureMessage without encrypting the message
		SecureMessage secureMessage = new SecureMessage(toUci, securityManager.getMyUci(), 
				toNode, communication.getLocalSensibleThingsNode());
		
		secureMessage.setPayload(SerializationUtils.serialize(message));
	
		if(securityManager.isSymmetricKeyValid(toUci, config.getSymmetricKeyLifeTime())){
			sendToPostOffice(secureMessage);
			securityManager.encapsulateSecueMessage(postOffice, toUci, password, password);
			sendOutSecureMessage(toUci);
			
		}else if(securityManager.hasCertificate(toUci)){
			exchangeSessionKey(toUci, toNode);			
			sendToPostOffice(secureMessage);
		}else{
			exchangeCertificate(toUci, toNode);
			sendToPostOffice(secureMessage);	
		}
	}
	
	/**
	 * Handle the received secure message
	 * 
	 * @param sm the received secure message
	 * @return then message encapsulated in the secure message
	 */
	public Message handleSecureMessage(SecureMessage sm){
		byte[] signature = sm.getSignature();
		byte[] payload = securityManager.decapsulateSecureMessage(sm, password);
		
		addToUciCache(sm.getFromNode().getAddress(), sm.fromUci);
		
		if(securityManager.verifySignature(payload, signature, sm.fromUci, config.getSignatureAlgorithm())){
			Message msg = (Message)SerializationUtils.deserialize(payload);
			return msg;
		}else{
			return null;
		}
				
	}

	/**
	 * Exchange Session Key</p>
	 * (2.2) If (IDD, KS, Lifetime) temporary key store doesn't exist, or Lifetime is invalid
	 *       C->D : E(PUD, KS) || E(PRC, H ([KS])) || E(KS, IDC || N1) || CertificateC
	 *              
	 * @param toUci the UCI of the receiver
	 * @param toNode the node of the receiver
	 */
	private void exchangeSessionKey(String toUci, SensibleThingsNode toNode) {
		
		SessionKeyExchangeMessage skxm = new SessionKeyExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
//		System.out.println("[Exchange Session Key] " + skxm);
		// generate the symmetric security key
		securityManager.generateSymmetricSecurityKey(toUci, config.getSymmetricAlgorithm(), config.getSymmetricKeyLength(), password, password);
		
		// set the payload
		byte[] secretKey = securityManager.getSecretKey(toUci, "password".toCharArray()).getEncoded();
		skxm.setPayload(securityManager.asymmetricEncryptMessage(toUci, secretKey, config.getAsymmetricAlgorithm()));
		skxm.setSignature(securityManager.signMessage(secretKey, config.getSignatureAlgorithm(), password));
		skxm.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		// set the secret key payload
		SecretKeyPayload secretKeyPayload = new SecretKeyPayload(securityManager.getMyUci(), toUci);
		
		// set nonce and add it to the data pool
		int nonce = new Random().nextInt();
		secretKeyPayload.setNonce(nonce);
		securityManager.addToNoncePool(toUci, nonce);
		
		byte[] payload = SerializationUtils.serialize(secretKeyPayload);
		skxm.setSecretKeyPayload(securityManager.symmetricEncryptMessage(toUci, payload, config.getSymmetricMode(), password));
		
		// set the iv, only for AES
		byte[] iv = securityManager.getIVparameter();
		if(iv != null){
			skxm.setIv(securityManager.symmetricEncryptIVParameter(toUci, iv, password));
		}
		
		// set the certificatePayload
		CertificatePayload certPayload = new CertificatePayload(securityManager.getMyUci(), toUci);
		certPayload.setCert(securityManager.getCertificate());
		
		byte[] certificatePayload = SerializationUtils.serialize(certPayload);
		
		skxm.setCertificatePayload(certificatePayload);		
		
		sendMessage(skxm);
		
	}
	
	/**
	 * Handle session key exchange message, sending back session key response message</p>
	 * 
	 * (2.3) D: store (IDC, KS, Lifetime) in temporary key store
	 *       D->C : E(KS, payload) || E(PRD, H(payload))
	 *       payload = IDD || IDC || N1 || N2
	 * 
	 * @param skxm session key exchange message
	 */
	public void handleSessionKeyExchangeMessage(SessionKeyExchangeMessage skxm) {
		
//		System.out.println("[Handle Session Key Exchange Message] " + skxm);
		
		boolean isValid = false;
		
		// if it contacted before, it jump checking the certificate 
		if(securityManager.isContactedBefore(skxm.fromUci)){
			isValid = true;
		}else{
			CertificatePayload certPayload = (CertificatePayload)SerializationUtils.deserialize(skxm.getCertificatePayload());
			
//			System.out.println("[Handle session key exchange message] " + certPayload.getCert());
			
			if(securityManager.isCertificateValid(certPayload.getCert(), skxm.fromUci)){
				isValid = true;
				securityManager.storeCertificate(skxm.fromUci, certPayload.getCert(), "password".toCharArray());
			}
		}
		
		if(isValid){
			// Decapsulate the secret key
			byte[] secretKey = 
					securityManager.asymmetricDecryptMessage(skxm.getPayload(), config.getAsymmetricAlgorithm(), password);
			
			// check the payload signature
			if(!securityManager.verifySignature(secretKey, skxm.getSignature(),
					securityManager.getPublicKey(skxm.fromUci), skxm.getSignatureAlgorithm())){
				System.out.println("[Handle Session Key Exchange Message] Signature Error");
				return;
			}
			
			byte[] payload = securityManager.decryptPayload(secretKey, skxm.getIv(),
					skxm.getSecretKeyPayload(), config.getSymmetricMode());
			
			SecretKeyPayload secretKeyPayload = (SecretKeyPayload) SerializationUtils.deserialize(payload);
			
			// check the id
			if(!secretKeyPayload.getFromUci().equals(skxm.fromUci)){
				System.out.println("[Handle Session Key Exchange Message] ID Error");
				return;
			}
				
			// store the session key
			securityManager.storeSecretKey(skxm.fromUci, secretKey, config.getSymmetricAlgorithm(),  password, password);
			
			// send back an response message
			SessionKeyResponseMessage responseMessage = new SessionKeyResponseMessage(skxm.fromUci,
					securityManager.getMyUci(), skxm.getFromNode(),
					communication.getLocalSensibleThingsNode());

			ResponsePayload responsePayload = new ResponsePayload(skxm.fromUci, securityManager.getMyUci());

			// set the nonce
			int nonce = new Random().nextInt();
			// set to nonce
			responsePayload.setToNonce(secretKeyPayload.getNonce());
			// set from nonce
			responsePayload.setFromNonce(nonce);
			// add the fromNonce to the data pool
			securityManager.addToNoncePool(skxm.fromUci, nonce);

			byte[] responsePayloadInByte = SerializationUtils.serialize(responsePayload);
			
			responseMessage.setSignature(securityManager.signMessage(responsePayloadInByte, 
					config.getSignatureAlgorithm(), password));
			responseMessage.setSignatureAlgorithm(config.getSignatureAlgorithm());
			
			responseMessage.setPayload(securityManager.symmetricEncryptMessage(
							skxm.fromUci, responsePayloadInByte,
							config.getSymmetricMode(), password));
			
			// set the iv parameter
			byte[] ivParameter =  securityManager.getIVparameter();
			if(ivParameter != null){
				responseMessage.setIv(securityManager.symmetricEncryptIVParameter(skxm.fromUci, ivParameter, password));
			}
			
			sendMessage(responseMessage);
		}
	}
	
	/**
	 * Handle session key response message</p>
	 * 
	 * (2.4) C->D : E(KS, M || N2 || E(PRC, H(M)))
	 * 
	 * @param skrm the session key response message
	 */
	public void handleSessionKeyResponseMessage(SessionKeyResponseMessage skrm) {
//		System.out.println("[Handle Session Key Response Message] " + skrm);
		
		byte[] payload = securityManager.decryptPayload(skrm.fromUci, skrm.getIv(),
				skrm.getPayload(), config.getSymmetricMode(), password);
		
		
		// verify the signature
		if(securityManager.verifySignature(payload, skrm.getSignature(), skrm.fromUci, skrm.getSignatureAlgorithm())){
			
			ResponsePayload responsePayload = (ResponsePayload)SerializationUtils.deserialize(payload);
			if(responsePayload.getToNonce() == (Integer)securityManager.getFromNoncePool(skrm.fromUci)){
				securityManager.removeFromNoncePool("nonce");
				
				// encrypt the message
				securityManager.encapsulateSecueMessage(postOffice, skrm.fromUci, password, password);
				sendOutSecureMessage(skrm.fromUci);
			}
		}else{
			System.out.println("[Handle session key response message] Signature Error");
		}
		
	}
	
	/**
	 * If (IDD, PUD, Validation) doesn't exist or invalid, Exchange certificate</p>
	 * 
	 * (3.1) C->D : Payload || E(PRC,[H(payload)])
	 *            Payload = IDC || CertificateC || TS1 
	 * 
	 * @param toUci the UCI of the receiver
	 * @param toNode the node of the receiver
	 */
	private void exchangeCertificate(String toUci, SensibleThingsNode toNode) {
		CertificateExchangeMessage cxm = new CertificateExchangeMessage(toUci, securityManager.getMyUci(),
				toNode, communication.getLocalSensibleThingsNode());
//		System.out.println("[Exchange Certificate] " + cxm);
		CertificateExchangePayload cxp = new CertificateExchangePayload(securityManager.getMyUci(), toUci);
		cxp.setCert(securityManager.getCertificate());
		cxp.setTimeStamp(System.currentTimeMillis());
		
		byte[] payload = SerializationUtils.serialize(cxp);
		cxm.setPayload(payload);
		cxm.setSignature(securityManager.signMessage(payload, config.getSignatureAlgorithm(), password));
		cxm.setSignatureAlgorithm(config.getSignatureAlgorithm());
		
		sendMessage(cxm);
	}
	
	
	/**
	 * Handle Certificate Exchange Message</p>
	 * 
	 * (3.2) D : verify the CertificateC
	 *    
	 *     D->C : E(PUC, Payload) || E(PRC, H(Payload)) || CertificateD
	 *            Payload = IDD || TS1 
	 * @param cxm the certificate exchange message
	 */
	public void handleCertificateExchangeMessage(CertificateExchangeMessage cxm) {
//		System.out.println("[Handle Certificate Exchange Message] " + cxm);
		//Decapsulte the Certificate
		byte[] payload = cxm.getPayload();
		CertificateExchangePayload cxp = (CertificateExchangePayload)SerializationUtils.deserialize(payload);
		Certificate cert = cxp.getCert();
		
		// check signature
		if(!securityManager.verifySignature(cxm.getPayload(), cxm.getSignature(), cert, cxm.getSignatureAlgorithm())){
			System.out.println("[Handle Certificate Exchange Message] Signature Error!");
			return;
		}
		

		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxm.fromUci, cert, "password".toCharArray());
			
			// send back response message
			CertificateExchangeResponseMessage cxrm = new CertificateExchangeResponseMessage(cxm.fromUci,
					securityManager.getMyUci(), cxm.getFromNode(), communication.getLocalSensibleThingsNode());
			
			cxrm.setCert(securityManager.getCertificate());
			cxrm.setUci(securityManager.asymmetricEncryptMessage(cxm.fromUci, 
					securityManager.getMyUci().getBytes(), config.getAsymmetricAlgorithm()));
			
			byte[] cxrmPayload = String.valueOf(cxp.getTimeStamp()).getBytes();
			
			cxrm.setPayload(securityManager.asymmetricEncryptMessage(cxm.fromUci, 
					cxrmPayload, config.getAsymmetricAlgorithm()));
			cxrm.setSignature(securityManager.signMessage(cxrmPayload, config.getSignatureAlgorithm(), password));
			cxrm.setSignatureAlgorithm(config.getSignatureAlgorithm());
			
			sendMessage(cxrm);
		}else{
			System.out.println("[Handle Certificate Exchange Message] Certificate Error!");
		}
		
	}
	
	/**
	 * Handle Certificate Exchange Response Message
	 * 
	 * (3.3) C : verify the CertificateD
	 *       C->D : E(PUD, E(PRC, [KS || Lifetime])) || E(KS, [IDC || N1])
	 * @param cxrm Certificate exchange response message
	 */
	public void handleCertificateExchangeResponseMessage(
			CertificateExchangeResponseMessage cxrm) {
//		System.out.println("[Handle Certificate Exchange Response Message] " + cxrm);
		
//		//Decapsulte the Certificate
	
		byte[] payload = securityManager.asymmetricDecryptMessage(cxrm.getPayload(), config.getAsymmetricAlgorithm(), password);
		Certificate cert = cxrm.getCert();
		
		// check signature
		if(!securityManager.verifySignature(payload, cxrm.getSignature(), cert, cxrm.getSignatureAlgorithm())){
			System.out.println("[Handle Certificate Exchange Response Message] Signature Error!");
			return;
		}
		
		String fromUci = new String(securityManager.asymmetricDecryptMessage(cxrm.getUci(), config.getAsymmetricAlgorithm(), password));
		
		// check the source ID and 
		if(!fromUci.equals(cxrm.fromUci)){
			System.out.println("[Handle Certificate Exchange Response Message] ID Error!");
			return;
		}
		
		// verify the certificate
		if (securityManager.isCertificateValid(cert, cxrm.fromUci)) {
			// store the certificate
			securityManager.storeCertificate(cxrm.fromUci, cert, "password".toCharArray());
			
			exchangeSessionKey(cxrm.fromUci, cxrm.getFromNode());
		}else{
			System.out.println("[Handle Certificate Exchange Message] Certificate Error!");
		}
	}
	
	/**
	 * Cache the address from the receiver and its corresponding UCI
	 * @param address the address
	 * @param uci the corresponding UCI
	 */
	public void addToUciCache(String address, String uci){
		if(uciCache.containsKey(address)){
			uciCache.remove(address);
		}
		uciCache.put(address, uci);
	}

	/**
	 * Get the UCI corresponding the specified address
	 * @param address
	 * @return the UCI corresponding the specified address
	 */
	public String getUciFromCache(String address){
		return uciCache.get(address);
	}
	
	/**
	 * Temporarily store the secure message
	 * @param sm the secure message to be stored
	 */
	private void sendToPostOffice(SecureMessage sm){
		String toUci = sm.toUci;
		if(postOffice.containsKey(toUci)){
			postOffice.get(toUci).add(sm);
		}else{
			postOffice.put(toUci, new Vector<SecureMessage>());
			postOffice.get(toUci).add(sm);
		}
	}
	
	/**
	 * Send out the secure message temporarily stored in post office
	 * @param toUci the UCI of the receiver
	 */
	private void sendOutSecureMessage(String toUci) {
		if(postOffice.containsKey(toUci)){
			Vector<SecureMessage> msgs = postOffice.get(toUci);
			for(int i = 0 ; i < msgs.size(); i++){
				SecureMessage sm = msgs.get(i);
				msgs.remove(i);
				
				sendMessage(sm);
			}
			
		}
	}
	
	/**
	 * Transform the communication, normally between SSL and RUDP.
	 * @param communicationType the specified communication type
	 */
	private void transformCommunication(String communicationType){
//		System.out.println("[" + securityManager.getMyUci() + 
//				" : Communication] communication type shift from "+ communication +  " to "+ communicationType + " mode");
		
//		try {
//			Thread.sleep(1000);
//		} catch (InterruptedException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		Communication origin = communication;
		
//		if(platform.isBehindNat()){
//			System.out.println("[Proxy]");
//			if(communicationType.equals("SSL")){
//				toNewCommunicaiton(Communication.PROXY_SSL);
//			}else if(communicationType.equals("RUDP")){
//				toNewCommunicaiton(Communication.PROXY_RUDP);
//			}
//		}else{
			if(communicationType.equals("SSL")){
				
				SslCommunication.initCommunicationPort = communication.getLocalSensibleThingsNode().getPort();
				toNewCommunicaiton(Communication.SSL);
				
			}else if(communicationType.equals("RUDP")){
				
				RUDPCommunication.initCommunicationPort = communication.getLocalSensibleThingsNode().getPort();
				toNewCommunicaiton(Communication.RUDP);
								
			}
//		}
		
		// shutdown the old communication
		origin.shutdown();
		communication.setMessageListeners(origin.getMessageListeners()); 
				
		// reset the communication in lookup service
//		core.getLookupService().setCommunication(communication);
		
//		System.out.println("[" + securityManager.getMyUci() + 
//				" : Communication] communication shift to " + communication );
	}
	
	/**
	 * Set up the new communication
	 * 
	 * @param communicationType specified communication type
	 */
	private void toNewCommunicaiton(String communicationType){
		Class<?> communicationLoader;
		try {
			communicationLoader = Class.forName(communicationType);
			communication = (Communication) communicationLoader.newInstance();
		} catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Send out each message
	 * @param message the message to be send out
	 */
	private void sendMessage(Message message){
		try {
			communication.sendMessage(message);
		} catch (DestinationNotReachableException e) {
			e.printStackTrace();
		}
	}
}
