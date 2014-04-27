package se.sensiblethings.disseminationslayer.communication.security.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.SecretKey;

import se.sensiblethings.disseminationslayer.communication.security.encryption.SymmetricEncryption;

public class KeyStoreJCEKS implements IKeyStore{
	
	public static final String KEY_STORE_TYPE = "jceks";
	
	private KeyStore ks = null;
	private String keyStoreFile = null;
	
	// public KeyStoreJCEKS(){}
	
	public KeyStoreJCEKS(String keyStoreFile, char[] password) throws IOException{
		
		File file = new File(keyStoreFile);
		// this file may not exist
		if(!file.exists()){
			// if this file not found, it should create a new one
			// then load the new one
			createKeyStore(keyStoreFile, password);
		}
		
		// "KeyStore" the file name, which stores the keys
		// "password" the password of the keystore
		loadKeyStore(keyStoreFile, password);
		
	}
	
	
	public void loadKeyStore(String keyStoreFile, char[] password) throws  IOException {
		
		try {
			ks = KeyStore.getInstance(KEY_STORE_TYPE);
			FileInputStream fis = new FileInputStream(keyStoreFile);
			ks.load(fis, password);
			
			if(fis != null) fis.close();
			
		} catch (KeyStoreException | FileNotFoundException | 
				NoSuchAlgorithmException | CertificateException e) {
			e.printStackTrace();
		}
		
		this.keyStoreFile = keyStoreFile;
	}
	
	private void updataKeyStore(char[] password){
		
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(keyStoreFile);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		try {
			ks.store(fos, password);
			
			if(fos != null) fos.close();
		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * There is a built-in default keystore implementation type known as
	 * "jks" that is provided by Sun Microsystems.
	 * It implements the keystore as a file, utilizing a proprietary keystore type (format).
	 * 
	 * It protects each private key with its own individual password,
	 * and also protects the integrity of the entire keystore with a (possibly different) password.
	 * 
	 * "jceks" is an alternate proprietary keystore format to "jks" that
	 * uses much stronger encryption in the form of Password-Based Encryption with Triple-DES.
	 * 
	 * Keystore type designations are not case-sensitive.
	 * "jks" can only store private keys and certificates but not secret keys
	 *  So here adopt "jceks" this type
	 *  
	 * @param KeyStoreFile
	 * @param password
	 */
	public void createKeyStore(String KeyStoreFile, char[] password){
		
		KeyStore ks = null;
		
		try {
			ks = KeyStore.getInstance(KEY_STORE_TYPE);
			//ks = KeyStore.getInstance(KeyStore.getDefaultType());
			
			// set the password
			ks.load(null, password);
			
			// Store away the keystore.
			FileOutputStream fos = new FileOutputStream(KeyStoreFile);
			ks.store(fos, password);
			if(fos != null){
				fos.close();
			}
		} catch (KeyStoreException| NoSuchAlgorithmException | CertificateException | IOException e) {
			
			e.printStackTrace();
		}
	}
	
	public Key getPublicKey(String alias){
		
		Key key = null;
		try {
			key = ks.getCertificate(alias).getPublicKey();
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	public Certificate getCertificate(String alias) throws KeyStoreException{
		return ks.getCertificate(alias);
	}
	
	
	public Key getPrivateKey(String alias, char[] privateKeyPassword) {
		
		Key key = null;
		try {
			PrivateKeyEntry pkEntry = (PrivateKeyEntry) ks.getEntry(alias,  new PasswordProtection(privateKeyPassword));
			key = pkEntry.getPrivateKey();
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	
	
	public Key getSecretKey(String alias, char[] secretKeyPassword){
		
		alias = addSecreKeyAliasSuffix(alias);
		
		Key key = null;
		try {
			SecretKeyEntry pkEntry = (SecretKeyEntry) ks.getEntry(alias,  new PasswordProtection(secretKeyPassword));
			key = pkEntry.getSecretKey();
			
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException
				| KeyStoreException e) {
			e.printStackTrace();
		}
		return key;
	}
	

	/**
	 * 
	 * @param alias
	 * @param privateKey
	 * @param password
	 * @param cert the self signed X509 v1 certificate
	 * @return
	 * @throws KeyStoreException
	 */
	public void storePrivateKey(String alias, 
			PrivateKey privateKey, 
			char[] privateKeyPassword, char[] keyStorePassword,
			Certificate[] certs) throws KeyStoreException{

		// the certificate chain is required to store the private key
		// Generate the certificate chain
		// password same as the keystore
		ks.setKeyEntry(alias, privateKey, privateKeyPassword, certs);
		
		// keystore password needed to write into file
		updataKeyStore(keyStorePassword);
		
	}
	
	public void storeSecretKey(String alias, byte[] secretKey, String keyType, char[] secretKeyPassword, char[] keyStorePassword) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		// firstly transform the secretKey
		SecretKey sk = (SecretKey)SymmetricEncryption.loadKey(secretKey, keyType);
		
		SecretKeyEntry skEntry = new SecretKeyEntry(sk);
		
		// adds the secret key suffix
		alias = addSecreKeyAliasSuffix(alias);
		
		ks.setEntry(alias, skEntry, new PasswordProtection(secretKeyPassword));
	
		// password needed to write into file
		updataKeyStore(keyStorePassword);
		
	}
	
	public void storeSecretKey(String alias, SecretKey secretKey, char[] secretKeyPassword, char[] keyStorePassword) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		SecretKeyEntry skEntry = new SecretKeyEntry(secretKey);
		
		// adds the secret key suffix
		alias = addSecreKeyAliasSuffix(alias);
		
		// ProtectionParameter implemented by PasswordProtection
		ks.setEntry(alias, skEntry, new PasswordProtection(secretKeyPassword));
		
		// password needed to write into file
		updataKeyStore(keyStorePassword);
		
	}
	
	public void storeCertificate(String alias, Certificate certificate, char[] keyStorePassword) throws KeyStoreException{
		
		//TrustedCertificateEntry cerEntry = new TrustedCertificateEntry(certificate);
		
		// The 3rd ProtectionParameter should be set null, otherwise it will throw an exception
		// This problem could be found from the source code at
		// "java.security.KeyStoreSpi.engineSetEntry(KeyStoreSpi.java:522)"
		//ks.setEntry(alias, cerEntry, new PasswordProtection(password));
		
		//ks.setEntry(alias, cerEntry, null);
		
		ks.setCertificateEntry(alias, certificate);
		// password needed to write into file
		updataKeyStore(keyStorePassword);
	}

	public void deleteCertificate(String alias, char[] keyStorePassword) throws KeyStoreException{
		ks.deleteEntry(alias);
		
		// password needed to write into file
		updataKeyStore(keyStorePassword);
	}
	
	public boolean hasKey(String alias){
		try {
			return ks.isKeyEntry(alias);
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean hasSecretKey(String alias){
		// adds the secret key alias
		alias = addSecreKeyAliasSuffix(alias);
		
		try {
			return hasKey(alias) && ks.entryInstanceOf(alias, SecretKeyEntry.class);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean hasPrivateKey(String alias){
		try {
			return hasKey(alias) && ks.entryInstanceOf(alias, PrivateKeyEntry.class);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean hasCertificate(String alias){
		try {
			return ks.isCertificateEntry(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public boolean containAlias(String alias){
		try {
			return ks.containsAlias(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	public Date getCreationData(String alias){
		
		try {
			return ks.getCreationDate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	public int getSize(){
		try {
			return ks.size();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return 0;
	}
	
	public X509Certificate getIssuredCertificate(String alias){
		Certificate[] chain = getCertificateChain(alias);
		
		if(chain != null){
			return (X509Certificate) chain[0];
		}else{
			return null;
		}
	}
	
	
	public Certificate[] getCertificateChain(String alias){
		try {
			return ks.getCertificateChain(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public Enumeration<String> getAllAlias(){
		try {
			return ks.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String toString() {
		String string = null;
		string =  "==KeyStoreJCA== \n[keyStoreFile] = " + keyStoreFile + "\n[Size] = "
				+ getSize() + "\n[All Alias] = ";
		
		for (Enumeration<String> e = getAllAlias(); e.hasMoreElements();)
		       string += e.nextElement()+", ";
		return string;
		
	}
	
	
	/**
	 * Adds the "/secretKey" suffix to the secrektyEntry alias
	 * 
	 * it may get collision or exception if the <code>TrustedCertificateEntry</code> call by <code>setEntry</code> or 
	 * an entry created by <code>setCertificateEntry</code> with the same uci exist
	 * so here it adds the suffix with "/certificate"
	 * 
	 * @param alias the alias needs suffix
	 * @return alias with the "/secretKey" suffix
	 */
	private String addSecreKeyAliasSuffix(String alias){
		return alias + "/secretKey";
	}
}
