package se.sensiblethings.disseminationslayer.communication.security.messagehandler;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.disseminationslayer.communication.security.certificate.CertificateOperations;
import se.sensiblethings.disseminationslayer.communication.security.configuration.SecurityConfiguration;
import se.sensiblethings.disseminationslayer.communication.security.encryption.AsymmetricEncryption;
import se.sensiblethings.disseminationslayer.communication.security.encryption.SymmetricEncryption;
import se.sensiblethings.disseminationslayer.communication.security.keystore.KeyStoreJCEKS;
import se.sensiblethings.disseminationslayer.communication.security.messagedigest.MessageDigestOperations;
import se.sensiblethings.disseminationslayer.communication.security.messages.SecureMessage;
import se.sensiblethings.disseminationslayer.communication.security.signature.SignatureOperations;

/**
 * SecurityManager.java
 * 
 * This class servers as middleware between up communication and below kinds of operations including key storing, 
 * encryption, decryption and  signature signing and verifying.
 * 
 * @author Hao
 *
 */
public class SecurityManager {
	
	// the operator is the uci who owns
	private String myUci = null;
	
	// the key store it uses to store the session keys and certificates, 
	// as well as its private key
	private KeyStoreJCEKS keyStore = null;
	
	private Map<String, Object> noncePool = null;
	private SecurityConfiguration config = null;
	
	/**
	 * Initialize the security manager
	 * 
	 * @param config the security configuration
	 */
	public SecurityManager(SecurityConfiguration config){
		this.config = config;
		noncePool = new HashMap<String, Object>();
	}
	
	/**
	 * Initialize the key store: set up or reload the key store file and generate the key pair if it doesn't have
	 * @param uci UCI of myself
	 * @param privateKeyPassword password to protect the private key
	 * @param keyStorePassword password to protect the key store
	 */
	public void initializeKeyStore(String uci, char[] privateKeyPassword, char[] keyStorePassword){
		setMyUci(uci);
		
		// transform the uci to formal file name without "/"
		String prefix = uci.replace("/", "_");
		
		String filePath = config.getKeyStoreFileDirectory() + prefix + "_" + config.getKeyStoreFileName();
		
		try {
			keyStore = new KeyStoreJCEKS(filePath, keyStorePassword);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		// check weather the store has the KeyPair
		if(!keyStore.hasKey(uci)){
			// if not, create the key pair
			CreateKeyPairAndCertificate(uci, privateKeyPassword, keyStorePassword);
		}
		
	}
	
	/**
	 * Set the security configuration
	 * @param config the security configuration
	 */
	public void setSecuiryConfiguraton(SecurityConfiguration config){
		this.config = config;
	}
	
	/**
	 * Get the UCI of myself
	 * @return return the UCI of myself
	 */
	public String getMyUci() {
		return myUci;
		
	}
	
	/**
	 * Set the UCI of myself
	 * @param myUci set the UCI of myself
	 */
	public void setMyUci(String myUci) {
		this.myUci = myUci;
	}

	/**
	 * Add the nonce to the temporary pool
	 * @param name the name mapping to this nonce
	 * @param value the value of this nonce, maybe a integer or a time stamp
	 */
	public void addToNoncePool(String name, Object value){
		noncePool.put(name, value);
	}
	
	/**
	 * Get the nonce from the pool through specified name
	 * @param name the name mapping to this nonce
	 * @return return the value of the nonce
	 */
	public Object getFromNoncePool(String name){
		return noncePool.get(name);
		
	}
	
	/**
	 * Remove the specified nonce from the pool
	 * @param name the name mapping to this nonce
	 * @return return true if removed successfully, false if no such nonce
	 */
	public boolean removeFromNoncePool(String name){
		if(noncePool.containsKey(name)){
			noncePool.remove(name);
			return true;
		}else{
			return false;
		}
	}
	
	/**
	 * Check whether the symmetric key valid of not
	 * 
	 * @param uci the UCI mapping to this key
	 * @param lifeTime the life time of the key
	 * @return return true if this key is valid, false if there is no such key in key store or this key is expired.
	 */
	public boolean isSymmetricKeyValid(String uci, long lifeTime){
		return keyStore.hasSecretKey(uci) &&
				checkKeyLifetime(keyStore.getCreationData(uci), lifeTime);
	}
	
	/**
	 * Check the key is expired or not
	 * @param creationTime the time when the key was stored
	 * @param lifeTime the life time of the key
	 * @return true if this key is not expired, otherwise false
	 */
	private boolean checkKeyLifetime(Date creationTime, long lifeTime){
		long time = (new Date().getTime() - creationTime.getTime()) ;
		if(time < lifeTime){
			return true;
		}else{
			return false;
		}
		
	}
	
	/**
	 * Check this UCI has registered or not, by observing the issued certificate
	 * @param myUci the UCI to be checked
	 * @param bootstrapUci the UCI of Bootstrap node
	 * @return true if it has registered, false it hasn't
	 */
	public boolean isRegisted(String myUci, String bootstrapUci){
		if(keyStore.getIssuedCertificate(myUci) == null){
			System.out.println("[" + myUci + "]" + "No issuered Certificate !");
			return false;
		}
		
		return keyStore.getIssuedCertificate(myUci).getIssuerX500Principal().getName().equals("CN="+bootstrapUci);
	}
	
	/**
	 * Decapsulate the secure message by decrypting the payload in this message
	 * @param sm the secure message to be operated
	 * @param secretKeyPassword the password to get the secret key from the key store
	 * @return the plain context in payload
	 */
	public byte[] decapsulateSecureMessage(SecureMessage sm, char[] secretKeyPassword){
		
		return decryptPayload(sm.fromUci, sm.getIv(), 
				sm.getPayload(), config.getSymmetricMode(), secretKeyPassword);
			
	}
	
	/**
	 * Encapsulate all secure message with specified receiver, by encrypt the payload context
	 * and sign the signature of the payload
	 * 
	 * @param postOffice the post office where temporarily store the up going messages
	 * @param toUci the UCI of the receiver
	 * @param secretKeyPassword the password to get the secret key
	 * @param privateKeyPassword the password to get the private key
	 */
	public void encapsulateSecueMessage(Map<String, Vector<SecureMessage>> postOffice, String toUci, char[] secretKeyPassword,
			char[] privateKeyPassword) {
		if(postOffice.containsKey(toUci)){
			Vector<SecureMessage> msgs = postOffice.get(toUci);
			
			for(int i = 0 ; i < msgs.size(); i++){
				SecureMessage sm = msgs.get(i);
				msgs.remove(i);
				
				byte[] message = sm.getPayload();
			
				sm.setPayload(symmetricEncryptMessage(toUci, message, config.getSymmetricMode(), secretKeyPassword));
				sm.setSignature(signMessage(message, config.getSignatureAlgorithm(), privateKeyPassword));
				sm.setSignatureAlgorithm(config.getSignatureAlgorithm());
				
				byte[] iv = getIVparameter();
				if(iv != null){
					sm.setIv(symmetricEncryptIVParameter(toUci, iv, secretKeyPassword));
				}
				
				msgs.add(sm);
			}
			
		}
	}
	
	/********************************************************************************
	 * 
	 *                           Certificate Part
	 ********************************************************************************/
	
	/**
	 * Generate the key pair and self signed certificate
	 * 
	 * @param uci the UCI of myself
	 * @param privateKeyPassword the password to protect the private key
	 * @param keyStorePassword the password to protect the key store
	 */
	protected void CreateKeyPairAndCertificate(String uci, char[] privateKeyPassword, char[] keyStorePassword){
		// sun.security.X509 package provides many APIs to use
		// e.g. CertAndKeyGen gen = new CertAndKeyGen(keyAlgName, sigAlgName, providerName);
		// it can generate the RSA keypair and self signed certificate
		// While it is not recommended to use sun.* packages
		// Reason to see : http://www.oracle.com/technetwork/java/faq-sun-packages-142232.html
		KeyPair keyPair = null;
		try {
			 keyPair = AsymmetricEncryption.generateKey(config.getAsymmetricAlgorithm(),
					 config.getAsymmetricKeyLength());
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
		// generate the self signed X509 v1 certificate
		// setting the subject name of the certificate
		// String subjectName = "CN=" + uci + ",OU=ComputerColleage,O=MIUN,C=Sweden";
		String subjectName = "CN=" + uci;
		
		// set the life time to 1 year
		Certificate cert = CertificateOperations.generateSelfSignedcertificate(subjectName, 
				keyPair, config.getAsymmetricKeyLifetime());
		
		// store the private key with the self signed certificate
		storePrivateKey(uci, keyPair.getPrivate(), privateKeyPassword, keyStorePassword, new Certificate[]{cert});
		
	}
	
	/**
	 * Check whether the certificate signing request is valid or not
	 * @param certRequest the certificate signing request to be checked
	 * @param fromUci the sender of this request
	 * @return true if this request valid, false not
	 */
	public boolean isCeritificateSigningRequestValid(
		PKCS10CertificationRequest certRequest, String fromUci) {
		
		// add the BouncyCastleProvider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// check the signature and the ID
		try {
			// verify the request using the BC provider
			if (certRequest.verify()
					&& certRequest.getCertificationRequestInfo().getSubject().toString().equals("CN="+fromUci)) {
				return true;
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {

			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Check if the certificate valid not
	 * 
	 * @param cert the certificate to be checked
	 * @param fromUci the UCI who owns the certificate
	 * @return true if this certificate is valid, false not
	 */
	public boolean isCertificateValid(Certificate cert, String fromUci){
		X509Certificate X509Cert = (X509Certificate) cert; 
		
		try {
			X509Cert.verify((PublicKey)keyStore.getPublicKey(config.getBootstrapUci()));
			X509Cert.checkValidity();
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			
			e.printStackTrace();
			return false;
		}
		
		if(! X509Cert.getSubjectX500Principal().getName().equals(toX500Name(fromUci)))
			return false;
		
		if(! X509Cert.getIssuerX500Principal().getName().equals(toX500Name(config.getBootstrapUci()))){
			return false;
		}
			
		return true;
	}
	
	/**
	 * Get the X500Name fromat name from normal UCI name
	 * @param name the normal UCI name
	 * @return the X500Name format name
	 */
	private String toX500Name(String name){
		return "CN=" + name;
	}
	
	/**
	 * Check whether if it has contacted the sender before
	 * @param fromUci the UCI of the sender
	 * @return true if the key store has the UCI of the sender, otherwise false
	 */
	public boolean isContactedBefore(String fromUci){
		return keyStore.containAlias(fromUci);
	}
	
	/**
	 * Sign the certificate signing request
	 * 
	 * @param certRequest the certificate signing request
	 * @param uci the UCI who sends the request
	 * @param privateKeyPassword the password to get the private key
	 * @param keyStorePassword the password to protect the key store
	 * @return the certificate chain including the issued certificate by Bootstrap and Bootstrap's root certificate
	 */
	public Certificate[] signCertificateSigningRequest(PKCS10CertificationRequest certRequest, String uci,
			char[] privateKeyPassword, char[] keyStorePassword){
		KeyPair keyPair = new KeyPair((PublicKey)keyStore.getPublicKey(myUci), 
									  (PrivateKey)keyStore.getPrivateKey(myUci, privateKeyPassword));
		Certificate[] certs = null;
		
		try {
			certs =  CertificateOperations.buildChain(certRequest, (X509Certificate)keyStore.getCertificate(myUci), keyPair, 
					config.getAsymmetricKeyLifetime());
			
			// store the issued certificate into keystore
			keyStore.storeCertificate(uci, certs[0], keyStorePassword);
			
		} catch (InvalidKeyException | CertificateParsingException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException | KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return certs;
	}
	
	/**
	 * Return itself certificate</p>
	 * 
	 * Before registration to the bootstrap, it retrieves the self signed root certificate
	 * with X509V1 version. Otherwise, it retrieves the bootstrap issued certificate from the 
	 * certificate chain in the keystore's <code>PrivateKeyEntry</code>. It is the first certificate
	 * in this certificate chain.
	 * 
	 * @return Certificate itself certificate
	 */
	public Certificate getCertificate(){
		try {
			return keyStore.getCertificate(myUci);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * Get the specified certificate with a UCI
	 * @param uci the UCI specifying the certificate
	 * @return  the specified certificate
	 */
	public Certificate getCertificate(String uci){
		try {
			return keyStore.getCertificate(uci);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * Check has the specified certificate or not
	 * @param uci the UCI specifying the certificate
	 * @return true if this key store has the specified certificate, otherwise false
	 */
	public boolean hasCertificate(String uci){
		if(uci == null){
			return false;
		}
		return keyStore.hasCertificate(uci);
		
	}
	
	/**
	 * Get the certificate signing request
	 * @param uci the UCI who want to send the certificate
	 * @param privateKeyPassword the password to get the private key
	 * @return the certificate signing request
	 */
	@SuppressWarnings("deprecation")
	public PKCS10CertificationRequest getCertificateSigingRequest(String uci, char[] privateKeyPassword){
		String subjectName = "CN=" + uci;
		
		KeyPair keyPair = new KeyPair((PublicKey)keyStore.getPublicKey(uci), 
									  (PrivateKey)keyStore.getPrivateKey(uci,  privateKeyPassword));
		
		return CertificateOperations.generateCertificateSigningRequest(subjectName, keyPair);
	}
	
	/**
	 * Store the certificate chain
	 * @param uci the UCI of myself
	 * @param certs the certificate chain to be stored
	 * @param privateKeyPassword the password to protect the private key
	 * @param keyStorePassword the password to protect the key store
	 */
	public void storeCertificateChain(String uci, Certificate[] certs, char[] privateKeyPassword, 
			char[] keyStorePassword){
		
		storePrivateKey(uci, (PrivateKey)keyStore.getPrivateKey(uci, privateKeyPassword), 
				privateKeyPassword, keyStorePassword, certs);
		
	}
	
	/**
	 * Store the private key with corresponding certificate chain
	 * @param uci the UCI of myself
	 * @param privateKey the private key to be stored
	 * @param privateKeyPassword the password to protect the private key
	 * @param keyStorePassword the password to protect the key store
	 * @param certs the corresponding certificate chain
	 */
	public void storePrivateKey(String uci, PrivateKey privateKey, char[] privateKeyPassword, 
			char[] keyStorePassword, Certificate[] certs){
		try {
			keyStore.storePrivateKey(uci, privateKey, privateKeyPassword, keyStorePassword, certs);

		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Store the certificate 
	 * @param uci the UCI of own the certificate
	 * @param cert the certificate to be stored
	 * @param keyStorePassword the password to protect the key store
	 */
	public void storeCertificate(String uci, Certificate cert, char[] keyStorePassword){
		
		try {
			keyStore.storeCertificate(uci, cert, keyStorePassword);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	/********************************************************************************
	 * 
	 *                           Signature Part
	 ********************************************************************************/
	
	/**
	 * Sign the message with specified algorithm
	 * @param message the message to be signed
	 * @param algorithm the specified algorithm
	 * @param privateKeyPassword  the password to protect the private key
	 * @return the signature of the message in string type
	 */
	public String signMessage(String message, String algorithm, char[] privateKeyPassword){
		
		return new String(signMessage(message.getBytes(), algorithm, privateKeyPassword));
	}
	
	/**
	 * Sign the message with specified algorithm
	 * @param message the message to be signed
	 * @param algorithm the specified algorithm
	 * @param privateKeyPassword the password to protect the private key
	 * @return the signature of the message in bytes
	 */
	public byte[] signMessage(byte[] message, String algorithm, char[] privateKeyPassword){
		// load the private key
		PrivateKey privateKey = (PrivateKey) keyStore.getPrivateKey(myUci,  privateKeyPassword);
		
		byte[] signature = null;
		try {
			signature = SignatureOperations.sign(message, privateKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return signature;
	}
	
	/**
	 * Verify the signature
	 * @param message the source message
	 * @param signature the corresponding signature to be checked
	 * @param fromUci the UCI who sign the message
	 * @param algorithm the algorithm used for this signature
	 * @return true if this signature is valid, otherwise false
	 */
	public boolean verifySignature(byte[] message, byte[] signature, String fromUci, String algorithm){
		return verifySignature(message, signature, (PublicKey)keyStore.getPublicKey(fromUci), algorithm);
	}
	
	/**
	 * Verify the signature
	 * @param message the source message in bytes
	 * @param signature the corresponding signature to be checked
	 * @param publicKey the public key that could be used for verifying
	 * @param algorithm the algorithm used for this signature
	 * @return true if this signature is valid, otherwise false
	 */
	public boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey, String algorithm){
		try {
			return SignatureOperations.verify(message, signature, publicKey, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Verify the signature
	 * @param message the source message in String type
	 * @param signature the corresponding signature to be checked
	 * @param publicKey the public key that could be used for verifying
	 * @param algorithm the algorithm used for this signature
	 * @return true if this signature is valid, otherwise false
	 */
	public boolean verifySignature(String message, String signature, PublicKey publicKey, String algorithm){
		
		return verifySignature(message.getBytes(),  signature.getBytes(), publicKey, algorithm);
	}
	
	/**
	 * Verify the signature
	 * @param message the source message in String type
	 * @param signature the corresponding signature in bytes to be checked
	 * @param cert the certificate containing the public key that could be used for verifying
	 * @param algorithm the algorithm used for this signature
	 * @return true if this signature is valid, otherwise false
	 */
	public boolean verifySignature(byte[] message, byte[] signature, Certificate cert, String algorithm){
		try {
			return SignatureOperations.verify(message, signature, cert, algorithm);
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Verify the signature
	 * @param message the source message in String type
	 * @param signature the corresponding signature in String type to be checked 
	 * @param cert the certificate containing the public key that could be used for verifying
	 * @param algorithm the algorithm used for this signature
	 * @return true if this signature is valid, otherwise false
	 */
	public boolean verifySignature(String message, String signature, Certificate cert, String algorithm){
		return verifySignature(message.getBytes(), signature.getBytes(), cert, algorithm);
	}
	
	
	/********************************************************************************
	 * 
	 *                           Asymmetric Encrypt Part
	 ********************************************************************************/
	
	/**
	 * Encrypt message with specified algorithm
	 * @param message the message to be encrypt
	 * @param algorithm the specified encryption algorithm
	 * @return the cipher text in String type
	 */
	public String asymmetricEncryptMessage(String toUci, String message, String algorithm){
		
		return  new String (asymmetricEncryptMessage(toUci, message.getBytes(), algorithm));
	}
	
	/**
	 * Encrypt message with specified algorithm
	 * @param toUci the receiver who to send this message to
	 * @param message the message to be encrypt
	 * @param algorithm the specified encryption algorithm
	 * @return the cipher text in bytes
	 */
	public byte[] asymmetricEncryptMessage(String toUci, byte[] message, String algorithm){
		
		PublicKey publicKey = (PublicKey)keyStore.getPublicKey(toUci);
		
		return AsymmetricEncryption.encrypt(publicKey, message, algorithm);
	}
	

	/**
	 * Decrypt message with specified algorithm
	 * @param message the message to be decrypt
	 * @param algorithm the specified algorithm
	 * @param privateKeyPassword the password protecting the private key
	 * @return the plain text in string type
	 */
	public String asymmetricDecryptMessage(String message, String algorithm, char[] privateKeyPassword){
		return new String(asymmetricDecryptMessage(message.getBytes(), algorithm, privateKeyPassword));
		
	}
	
	/**
	 * Decrypt message with specified algorithm
	 * @param message  the message to be decrypt
	 * @param algorithm the specified algorithm
	 * @param privateKeyPassword the password protecting the private key
	 * @return the plain text in bytes
	 */
	public byte[] asymmetricDecryptMessage(byte[] message, String algorithm, char[] privateKeyPassword){
		// load the private key
		PrivateKey privateKey = (PrivateKey)keyStore.getPrivateKey(myUci, privateKeyPassword);
		
		return AsymmetricEncryption.decrypt(privateKey, message, algorithm);
	}
	
	/**
	 * Return the public key of myself
	 * @return Return the public key of myself
	 */
	public PublicKey getPublicKey() {
		return (PublicKey) keyStore.getPublicKey(myUci);
	}
	
	/**
	 * Return the specified key by UCI
	 * @param uci the UCi specifying the the key
	 * @return Return the specified key by UCI
	 */
	public PublicKey getPublicKey(String uci){
		return (PublicKey) keyStore.getPublicKey(uci);
	}
	
	/********************************************************************************
	 * 
	 *                           Symmetric Encrypt Part
	 ********************************************************************************/
	/**
	 * Symmetric decrypt the paylaod with specified mode
	 * @param secretKey the key to decrypt the payload
	 * @param iv  the initialization vector
	 * @param payload the payload in bytes to be decrypt
	 * @param symmetricMode the symmetric cipher mode
	 * @return the plain context of the payload
	 */
	public byte[] decryptPayload(byte[] secretKey, byte[] iv, byte[] payload, String symmetricMode){
		if(iv != null){
			byte[] IV = symmetricDecryptIVparameter(secretKey, iv);
			return symmetricDecryptMessage(secretKey, payload, IV, symmetricMode);
		}else{
			return symmetricDecryptMessage(secretKey, payload, symmetricMode);
		}
	}
	
	/**
	 * Symmetric decrypt the paylaod with specified mode
	 * @param fromUci the UCI who sends the message
	 * @param iv the initialization vector
	 * @param payload the payload in bytes to be decrypt
	 * @param symmetricMode the symmetric cipher mode
	 * @param secretkeyPassword the password protecting the secret key
	 * @return the plain context of the payload
	 */
	public byte[] decryptPayload(String fromUci, byte[] iv, byte[] payload, String symmetricMode, char[] secretkeyPassword){
		if(iv != null){
			byte[] IV = symmetricDecryptIVparameter(fromUci, iv, secretkeyPassword);
			return symmetricDecryptMessage(fromUci, payload, IV, symmetricMode, secretkeyPassword);
		}else{
			return symmetricDecryptMessage(fromUci, payload, symmetricMode, secretkeyPassword);
		}
	}
	
	/**
	 * Encrypt the initialization vector with "AES/ECB" mode
	 * @param toUci the UCI who sends to
	 * @param iv the initialization vector
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the cipher text of the IV in bytes
	 */
	public byte[] symmetricEncryptIVParameter(String toUci, byte[] iv, char[] secreKeyPassword){
		return symmetricEncryptMessage(toUci, iv, "AES/ECB/PKCS5Padding", secreKeyPassword);
	}
	
	/**
	 * Decrypt the initialization vector(IV) with "AES/ECB" mode
	 * @param fromUci the UCI who sends from
	 * @param raw the cipher text of the IV
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the plain text of the IV in bytes
	 */
	public byte[] symmetricDecryptIVparameter(String fromUci, byte[] raw, char[] secreKeyPassword){
		return symmetricDecryptMessage(fromUci, raw, "AES/ECB/PKCS5Padding", secreKeyPassword);
	}
	
	/**
	 * Decrypt the initialization vector(IV) with "AES/ECB" mode
	 * @param secretKey the key used to decrypt the IV
	 * @param raw the cipher text of the IV
	 * @return the plain text of the IV in bytes
	 */
	public byte[] symmetricDecryptIVparameter(byte[] secretKey, byte[] raw){
		return symmetricDecryptMessage(secretKey, raw, "AES/ECB/PKCS5Padding");
	}
	
	/**
	 * Get the instant initialization vector(IV)
	 * @return the instant initialization vector(IV)
	 */
	public byte[] getIVparameter(){
		if(SymmetricEncryption.getIVparameter() == null)
			return null;
		return SymmetricEncryption.getIVparameter().getIV();
	}
	
	/**
	 * Symmetric encrypt the message with specified algorithm
	 * @param toUci the message who sends to
	 * @param message the message to be encrypt
	 * @param algorithmModePadding encryption algorithm, mode and padding
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the cipher text of the message in string type
	 */
	public String symmetricEncryptMessage(String toUci, String message, String algorithmModePadding, char[] secreKeyPassword){
		
		return new String(symmetricEncryptMessage(toUci, message.getBytes(), algorithmModePadding, secreKeyPassword));
	}
	
	/**
	 * Symmetric encrypt the message with specified algorithm
	 * @param toUci the message who sends to
	 * @param message the message to be encrypt
	 * @param algorithmModePadding encryption algorithm, mode and padding
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the cipher text of the message in bytes
	 */
	public byte[] symmetricEncryptMessage(String toUci, byte[] message, String algorithmModePadding, char[] secreKeyPassword){
		// symmetric encryption
		SecretKey secretKey = (SecretKey) keyStore.getSecretKey(toUci, secreKeyPassword);
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.encrypt(secretKey, message, algorithmModePadding);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return plainText;
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param fromUci the message who sends from
	 * @param message the message to be decrypt
	 * @param algorithmModePadding encryption algorithm, mode and padding
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the plain text of the message in bytes
	 */
	public String symmetricDecryptMessage(String fromUci, String message, String algorithmModePadding, char[] secreKeyPassword){
		
		return new String(symmetricDecryptMessage(fromUci, message.getBytes(), algorithmModePadding, secreKeyPassword));
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param secretKey the secret key used to decrypt the message
	 * @param message the message to be decrypt
	 * @param algorithmModePadding encryption algorithm, mode and padding
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(SecretKey secretKey, byte[] message, String algorithmModePadding){
		
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.decrypt(secretKey, message, algorithmModePadding);
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

		return plainText;
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param fromUci the message who sends from
	 * @param message the message to be decrypt
	 * @param algorithmModePadding encryption algorithm, mode and padding
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(String fromUci, byte[] message, String algorithmModePadding, char[] secreKeyPassword){
		SecretKey secretKey = (SecretKey) keyStore.getSecretKey(fromUci, secreKeyPassword);
		
		return symmetricDecryptMessage(secretKey, message, algorithmModePadding);
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param secretKey the secret key used to decrypt the message
	 * @param message the message to be decrypt
	 * @param algorithmModePadding decryption algorithm, mode and padding
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(byte[] secretKey, byte[] message, String algorithmModePadding){
		// load the secret key
		SecretKey key = symmetricLoadKey(secretKey, algorithmModePadding.split("/")[0]);
		
		return symmetricDecryptMessage(key, message, algorithmModePadding);
	}
	
	/**
	 * load the secret key from bytes
	 * @param secretKey the secret key in bytes
	 * @param algorithm the corresponding algorithm used for with this key
	 * @return a instance of the secret key
	 */
	private SecretKey symmetricLoadKey(byte[] secretKey, String algorithm){
		SecretKey key = null;
		
		key = (SecretKey)SymmetricEncryption.loadKey(secretKey, algorithm);
		
		return key;
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param secretKey the secret key used to decrypt the message
	 * @param message  the message to be decrypt
	 * @param iv  the initialization vector
	 * @param algorithmModePadding decryption algorithm, mode and padding
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(SecretKey secretKey, byte[] message, byte[] iv, String algorithmModePadding){
		
		byte[] plainText = null;
		try {
			plainText = SymmetricEncryption.decrypt(secretKey, message, algorithmModePadding, new IvParameterSpec(iv));
			
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}

		return plainText;
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param fromUci the message who sends from
	 * @param message the message to be decrypt
	 * @param iv  the initialization vector
	 * @param algorithmModePadding decryption algorithm, mode and padding
	 * @param secreKeyPassword the password protecting the secret key
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(String fromUci, byte[] message, byte[] iv, String algorithmModePadding, char[] secreKeyPassword){
		SecretKey secretKey = (SecretKey) keyStore.getSecretKey(fromUci, secreKeyPassword);
		
		return symmetricDecryptMessage(secretKey, message, iv, algorithmModePadding);
	}
	
	/**
	 * Symmetric decrypt the message with specified algorithm
	 * @param secretKey the secret key used to decrypt the message
	 * @param message the message to be decrypt
	 * @param iv the initialization vector
	 * @param algorithmModePadding decryption algorithm, mode and padding
	 * @return the plain text of the message in bytes
	 */
	public byte[] symmetricDecryptMessage(byte[] secretKey, byte[] message, byte[] iv, String algorithmModePadding){
		// load the secret key
		SecretKey key = symmetricLoadKey(secretKey, algorithmModePadding.split("/")[0]);
		
		return symmetricDecryptMessage(key, message, iv, algorithmModePadding);
	}
	
	/**
	 * Generate the symmetric security key with specified algorithm, key length, and store it
	 * @param uci the UCI who shares this secret key together
	 * @param algorithm the algorithm used for this key
	 * @param length the key length
	 * @param secreKeyPassword the password protecting the secret key
	 * @param keyStorePassword the password protecting the key store
	 * @return true if generating and storing of the secret key successfully, otherwise false
	 */
	public boolean generateSymmetricSecurityKey(String uci, String algorithm, 
			int length, char[] secreKeyPassword, char[] keyStorePassword){
		
		// generate the symmetric key
		SecretKey secretKey = null;
		
		try {
			secretKey = SymmetricEncryption.generateKey(algorithm, length);
			
			// store the security key
			storeSecretKey(uci, secretKey, secreKeyPassword, keyStorePassword);
			
			return true;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return false;
	}
	
	/**
	 * Store the secret key
	 * @param uci the secret key who share with
	 * @param secretKey the secret key
	 * @param secretKeyPassword the password protecting the secret key
	 * @param keyStorePassword the password protecting the key store
	 */
	public void storeSecretKey(String uci, SecretKey secretKey, char[] secretKeyPassword, char[] keyStorePassword){
		try {
			keyStore.storeSecretKey(uci, secretKey, secretKeyPassword, keyStorePassword);
		} catch (InvalidKeyException | KeyStoreException
				| NoSuchAlgorithmException | InvalidKeySpecException e) {
			
			e.printStackTrace();
		}
	}
	
	/**
	 * Store the secret key
	 * @param uci the secret key who share with
	 * @param secretKey  the secret key in bytes
	 * @param algorithm the algorithm used for this key
	 * @param secretKeyPassword the password protecting the secret key
	 * @param keyStorePassword the password protecting the key store
	 */
	public void storeSecretKey(String uci, byte[] secretKey, String algorithm, char[] secretKeyPassword, char[] keyStorePassword){
		SecretKey key = symmetricLoadKey(secretKey, algorithm);
		storeSecretKey(uci, key, secretKeyPassword, keyStorePassword);
	}
	
	/**
	 * Get the secret key from the key store
	 * @param uci the UCI specifying the secret key
	 * @param secretKeyPassword the password to get the secret key
	 * @return the secret key from the key store
	 */
	public Key getSecretKey(String uci, char[] secretKeyPassword) {

		return keyStore.getSecretKey(uci, secretKeyPassword);
	}
	
	/**
	 * Check if the key store has the specified secret key
	 * @param uci the UCI specifying the secret key
	 * @return true if the key store has, otherwise false
	 */
	public boolean hasSecretKey(String uci){
		return keyStore.hasSecretKey(uci);
	}
	
	/********************************************************************************
	 * 
	 *                           Digest Part
	 ********************************************************************************/
	
	/**
	 * Return the digest of the message
	 * @param message the message where the digest gets from
	 * @param algorithm the digest algorithm
	 * @return the digest of the message
	 */
	public String digestMessage(String message, String algorithm){
		
		return new String(MessageDigestOperations.encode(message.getBytes(), algorithm));
	}
	
}
