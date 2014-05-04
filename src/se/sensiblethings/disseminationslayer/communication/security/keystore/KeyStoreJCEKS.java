package se.sensiblethings.disseminationslayer.communication.security.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
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

/**
 * KeyStoreJCEKS.java
 * 
 * This class implements all key store functions for security communication
 * It includes storing / getting the secret keys and certificates of others and self.
 * 
 * And there two kinds of keystore, "jceks" and "jks". As "jks" do not support secret key storing,
 * "jceks" is prefered here.
 * 
 * @author Hao
 *
 */
public class KeyStoreJCEKS implements IKeyStore{
	
	/**
	 * The key store type
	 */
	public static final String KEY_STORE_TYPE = "jceks";
	
	private KeyStore ks = null;
	private String keyStoreFile = null;
	
	/**
	 * The initialization of the key store: create new key store or
	 * load an existing key store with corresponding password.
	 * 
	 * @param keyStoreFile the key store file if it exist
	 * @param password the corresponding key store password, or new password for the new key store file
	 * @throws IOException
	 */
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
	
	/**
	 * Load the key store from a existing key store file
	 * 
	 * @param keyStoreFile the key store file
	 * @param password the corresponding key store password
	 * @throws IOException
	 */
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
	
	/**
	 * Update the key store with corresponding password
	 * 
	 * @param password the corresponding key store password
	 */
	private void updateKeyStore(char[] password){
		
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
	 * @param KeyStoreFile the path of the key store file 
	 * @param password the corresponding key store password
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
	
	/**
	 * Get the public key from the key store with specified alias (UCI)
	 * 
	 * @param alias specified alias name for this key
	 * @return the public key storing in the key store
	 */
	public Key getPublicKey(String alias){
		
		Key key = null;
		try {
			key = ks.getCertificate(alias).getPublicKey();
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return key;
	}
	
	/**
	 * Get the certificate from the key store with specified alias (UCI)
	 * 
	 * @param alias the specified alias name for this key
	 * @return the certificate storing in the key store
	 * @throws KeyStoreException
	 */
	public Certificate getCertificate(String alias) throws KeyStoreException{
		return ks.getCertificate(alias);
	}
	
	/**
	 * Get the certificate from the key store with specified alias (UCI) and corresponding private key password
	 * 
	 * @param alias the specified alias name for this key
	 * @param privateKeyPassword the password for this private key
	 * @return the private key storing in the key store
	 */
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
	
	/**
	 * Get the secret key from this key store with specified alias (UCI) and corresponding secret key password
	 * 
	 * @param alias the specified alias name for this key
	 * @param secretKeyPassword the password for this private key
	 * @return the secret key storing in the key store
	 */
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
	 * Store the private key. Corresponding certificate chain is required to store
	 * at the same time. 
	 * 
	 * @param alias the specified alias name for this key
	 * @param privateKey the key that will be stored
	 * @param privateKeyPassword the password to protect the key
	 * @param keyStorePassword the password to protect/update the key store
	 * @param certs corresponding certificate chain
	 * @throws KeyStoreException
	 */
	public void storePrivateKey(String alias, 
			PrivateKey privateKey, 
			char[] privateKeyPassword, char[] keyStorePassword,
			Certificate[] certs) throws KeyStoreException{

		// the certificate chain is required to store with the private key
		ks.setKeyEntry(alias, privateKey, privateKeyPassword, certs);
		
		// keystore password needed to write changes into file
		updateKeyStore(keyStorePassword);
	}
	
	/**
	 * Store secret key from bytes with specified key type. Passwords for secret key and key store are needed.
	 * 
	 * Pay attention that, <code> SecretKeyEntry</code> and <code>TrustedCertificateEntry</code> call by <code>setEntry</code> or 
	 * an entry created by <code>setCertificateEntry</code>, with the same alias are not allowed to store them at the
	 * same time. One solution here is add an suffix to this alias.
	 * 
	 * @param alias the specified alias name for this key
	 * @param secretKey secret key in bytes. It should be transformed to an instance before storing. 
	 * @param keyType the type of the secret key (AES, RC4, DES3, DES)
	 * @param secretKeyPassword the password to protect the secret key
	 * @param keyStorePassword the password to protect the key store
	 * @throws KeyStoreException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void storeSecretKey(String alias, byte[] secretKey, String keyType, char[] secretKeyPassword, char[] keyStorePassword) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		// firstly transform the secretKey
		SecretKey sk = (SecretKey)SymmetricEncryption.loadKey(secretKey, keyType);
		
		SecretKeyEntry skEntry = new SecretKeyEntry(sk);
		
		// adds the secret key suffix
		alias = addSecreKeyAliasSuffix(alias);
		
		ks.setEntry(alias, skEntry, new PasswordProtection(secretKeyPassword));
	
		// password needed to write into file
		updateKeyStore(keyStorePassword);
		
	}
	
	/**
	 * Store secret key. Passwords for secret key and key store are needed.
	 * 
	 * Pay attention that, <code> SecretKeyEntry</code> and <code>TrustedCertificateEntry</code> call by <code>setEntry</code> or 
	 * an entry created by <code>setCertificateEntry</code>, with the same alias are not allowed to store them at the
	 * same time. One solution here is to add an suffix to this alias.
	 * 
	 * @param alias the specified alias name for this key
	 * @param secretKey secret key to be stored
	 * @param secretKeyPassword the password to protect the secret key
	 * @param keyStorePassword the password to protect the key store
	 * @throws KeyStoreException if the keystore has not been initialized (loaded), or if this operation fails for some other reason
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void storeSecretKey(String alias, SecretKey secretKey, char[] secretKeyPassword, char[] keyStorePassword) throws 
	KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException{
		
		SecretKeyEntry skEntry = new SecretKeyEntry(secretKey);
		
		// adds the secret key suffix
		alias = addSecreKeyAliasSuffix(alias);
		
		// ProtectionParameter implemented by PasswordProtection
		ks.setEntry(alias, skEntry, new PasswordProtection(secretKeyPassword));
		
		// password needed to write into file
		updateKeyStore(keyStorePassword);
		
	}
	
	/**
	 * Store the certificate. 
	 * 
	 * But there is one problem that if you use <code>TrustedCertificateEntry</code> to store
	 * the certificate, the 3rd ProtectionParameter should be set null(<code>ks.setEntry(alias, cerEntry, null)</code>), 
	 * otherwise it will throw an exception.</p>
	 * This problem could be found from the source code at
	 * "java.security.KeyStoreSpi.engineSetEntry(KeyStoreSpi.java:522)"
	 * <code>ks.setEntry(alias, cerEntry, new PasswordProtection(password))</code>
	 * 
	 * @param alias the specified alias name for this key
	 * @param certificate certificate to be stored
	 * @param keyStorePassword the password protecting the key store
	 * @throws KeyStoreException if the keystore has not been initialized, or the given alias already exists and does not identify an 
	 * entry containing a trusted certificate, or this operation fails for some other reason.
	 */
	public void storeCertificate(String alias, Certificate certificate, char[] keyStorePassword) throws KeyStoreException{
		
		//TrustedCertificateEntry cerEntry = new TrustedCertificateEntry(certificate);
		
		// The 3rd ProtectionParameter should be set null, otherwise it will throw an exception
		// This problem could be found from the source code at
		// "java.security.KeyStoreSpi.engineSetEntry(KeyStoreSpi.java:522)"
		// ks.setEntry(alias, cerEntry, new PasswordProtection(password));
		
		//ks.setEntry(alias, cerEntry, null);
		
		ks.setCertificateEntry(alias, certificate);
		// password needed to write into file
		updateKeyStore(keyStorePassword);
	}
	
	/**
	 * Delete the certificate.
	 * 
	 * @param alias the specified alias name for this key
	 * @param keyStorePassword the password protecting the key store
	 * @throws KeyStoreException
	 */
	public void deleteCertificate(String alias, char[] keyStorePassword) throws KeyStoreException{
		ks.deleteEntry(alias);
		
		// password needed to write into file
		updateKeyStore(keyStorePassword);
	}
	
	/**
	 * Returns true if the entry identified by the given alias was created by a call to setKeyEntry, 
	 * or created by a call to setEntry with a PrivateKeyEntry or a SecretKeyEntry.
	 * 
	 * @param alias the alias for the keystore entry to be checked
	 * @return true if the entry identified by the given alias is a key-related entry, false otherwise.
	 */
	public boolean hasKey(String alias){
		try {
			return ks.isKeyEntry(alias);
		} catch (KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Returns true if the entry identified by the given alias was created by a call to 
	 * setEntry with a SecretKeyEntry. 
	 * 
	 * @param alias the alias for the keystore entry to be checked
	 * @return true if the entry identified by the given alias is a Secret Key entry, false otherwise.
	 */
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
	
	/**
	 * Returns true if the entry identified by the given alias was created by a call to
	 * setEntry with a PrivateKeyEntry. 
	 * 
	 * @param alias the alias for the keystore entry to be checked
	 * @return true if the entry identified by the given alias is a Private Key entry, false otherwise.
	 */
	public boolean hasPrivateKey(String alias){
		try {
			return hasKey(alias) && ks.entryInstanceOf(alias, PrivateKeyEntry.class);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Returns true if the entry identified by the given alias was created by a call to 
	 * setCertificateEntry, or created by a call to setEntry with a TrustedCertificateEntry.
	 * @param alias the alias for the keystore entry to be checked
	 * @return true if the entry identified by the given alias contains a trusted certificate, false otherwise.
	 */
	public boolean hasCertificate(String alias){
		try {
			return ks.isCertificateEntry(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Checks if the given alias exists in this keystore.
	 * 
	 * @param alias the alias name
	 * @return true if the alias exists, false otherwise
	 */
	public boolean containAlias(String alias){
		try {
			return ks.containsAlias(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Returns the creation date of the entry identified by the given alias.
	 * @param alias the alias name
	 * @return the creation date of this entry, or null if the given alias does not exist
	 */
	public Date getCreationData(String alias){
		
		try {
			return ks.getCreationDate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Retrieves the number of entries in this keystore.
	 * @return the number of entries in this keystore
	 */
	public int getSize(){
		try {
			return ks.size();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return 0;
	}
	
	/**
	 * Return the issued certificate by Bootstrap
	 * @param alias the alias name
	 * @return the issued certificate by Bootstrap
	 */
	public X509Certificate getIssuedCertificate(String alias){
		Certificate[] chain = getCertificateChain(alias);
		
		if(chain != null){
			return (X509Certificate) chain[0];
		}else{
			return null;
		}
	}
	
	/**
	 * Returns the certificate chain associated with the given alias. 
	 * The certificate chain must have been associated with the alias by a call to setKeyEntry, 
	 * or by a call to setEntry with a PrivateKeyEntry.
	 * 
	 * @param alias the alias name
	 * @return the certificate chain (ordered with the user's certificate first followed by zero or more certificate authorities), 
	 * or null if the given alias does not exist or does not contain a certificate chain
	 */
	public Certificate[] getCertificateChain(String alias){
		try {
			return ks.getCertificateChain(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Lists all the alias names of this keystore.
	 * @return enumeration of the alias names
	 */
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
	 * it may get collision or exception if the <code>TrustedCertificateEntry</code>  with the same uci exist
	 * so here it adds the suffix with "/secretKey"
	 * 
	 * @param alias the alias needs suffix
	 * @return alias with the "/secretKey" suffix
	 */
	private String addSecreKeyAliasSuffix(String alias){
		return alias + "/secretKey";
	}
}
