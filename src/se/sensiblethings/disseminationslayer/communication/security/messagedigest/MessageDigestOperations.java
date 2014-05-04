package se.sensiblethings.disseminationslayer.communication.security.messagedigest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MessageDigestOperation.java
 * 
 * Get the digest of the message with specified algorithm
 * @author Hao
 *
 */
public class MessageDigestOperations {
	/**
	 * SHA-1 algorithm
	 */
	public static final String SHA1 = "SHA-1";
	/**
	 * MD5 algorithm
	 */
	public static final String MD5 = "MD5";
	/**
	 * SHA-256 algorithm
	 */
	public static final String SHA256 = "SHA-256";
	
	/**
	 * Get the digest of the message with specified algorithm
	 * 
	 * @param message the message that generate the digest
	 * @param algorithm the digest algorithm
	 * @return
	 */
	public static byte[] encode(byte[] message, String algorithm){
		try {
			MessageDigest messagedigest = MessageDigest.getInstance(algorithm);
			messagedigest.update(message);
			return messagedigest.digest();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
