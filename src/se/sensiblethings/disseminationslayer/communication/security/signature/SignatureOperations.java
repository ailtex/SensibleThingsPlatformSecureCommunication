package se.sensiblethings.disseminationslayer.communication.security.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

/**
 * SignatureOperation.java
 * 
 * This class implements two operations (Signing and verifying) about signature of the messages
 * @author Hao
 *
 */
public class SignatureOperations {
	/**
	 * Signature algorithm: SHA1withRSA
	 */
	public static final String SHA1WITHRSA = "SHA1withRSA";
	/**
	 * Signature algorithm: SHA256withRSA
	 */
	public static final String SHA256WITHRSA = "SHA256withRSA";
	
	/**
	 * Retrieve the signature of the given message with specified algorithm
	 * 
	 * @param message the message to be signed
	 * @param privateKey the private key used to sign the message
	 * @param algorithm signature algorithm
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static byte[] sign(byte[] message, PrivateKey privateKey, String algorithm) throws 
	NoSuchAlgorithmException, InvalidKeyException{
		
		byte[] sig = null;
		
		Signature signature = Signature.getInstance(algorithm);
		signature.initSign(privateKey, new SecureRandom());
		
		try {
			signature.update(message);
			sig = signature.sign();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return sig;
	}
	
	/**
	 * Verify the signature of the message
	 * 
	 * @param message the message to be checked
	 * @param sigBytes the signature of the message
	 * @param publicKey the public key used to check the signature
	 * @param algorithm the signature algorithm
	 * @return True if the signature if valid, false if not
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static boolean verify(byte[] message, byte[] sigBytes, PublicKey publicKey, String algorithm) throws 
	NoSuchAlgorithmException, InvalidKeyException{
		
		Signature signature = Signature.getInstance(algorithm);
		signature.initVerify(publicKey);
		
		try {
			signature.update(message);
			return signature.verify(sigBytes);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Verify the signature of the message
	 * 
	 * @param message  the message to be checked
	 * @param sigBytes the signature of the message
	 * @param cert the certificate containing the corresponding public key used for verifying
	 * @param algorithm the signature algorithm
	 * @return True if the signature if valid, false if not
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static boolean verify(byte[] message, byte[] sigBytes, Certificate cert, String algorithm )throws 
	NoSuchAlgorithmException, InvalidKeyException{
		
		Signature signature = Signature.getInstance(algorithm);
		signature.initVerify(cert);
		
		try {
			signature.update(message);
			return signature.verify(sigBytes);
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return false;
	}
}
