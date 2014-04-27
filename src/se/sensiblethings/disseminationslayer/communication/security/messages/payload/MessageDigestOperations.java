package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestOperations {
	public static final String SHA1 = "SHA-1";
	public static final String MD5 = "MD5";
	public static final String SHA256 = "SHA-256";
	
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
