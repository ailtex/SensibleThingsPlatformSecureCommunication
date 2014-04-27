package se.sensiblethings.disseminationslayer.communication.security.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

public class SignatureOperations {
	
	public static final String SHA1WITHRSA = "SHA1withRSA";
	public static final String SHA256WITHRSA = "SHA256withRSA";
	
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
