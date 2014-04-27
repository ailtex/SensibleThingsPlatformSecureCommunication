package se.sensiblethings.disseminationslayer.communication.security.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryption {
	// These are encryption algorithms
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String DESede = "DESede";
	public static final String RC4 = "ARCFOUR";
	
	// These are  encryption modes with different same padding
	public static final String DES_ECB_PKCS5 = "DES/ECB/PKCS5Padding";
	public static final String DES_CBC_PKCS5 = "DES/CBC/PKCS5Padding";
	
	public static final String DESede_CBC_PKCS5 = "DESede/CBC/PKCS5Padding";
	public static final String DESede_ECB_PKCS5 = "DESede/ECB/PKCS5Padding";
	
	public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
	public static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
	public static final String AES_CFB_PKCS5 = "AES/CFB/PKCS5Padding";
	public static final String AES_OFB_PKCS5 = "AES/OFB/PKCS5Padding";
	public static final String AES_PCBC_PKCS5 = "AES/PCBC/PKCS5Padding";
	public static final String AES_CTR_PKCS5 = "AES/CTR/PKCS5Padding";
	
	private static IvParameterSpec initializationVector = null;
	
	public static SecretKey generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		
		keyGenerator.init(keyLength, new SecureRandom());
		return keyGenerator.generateKey();
	}
	
	public static Key loadKey(byte[] key, String algorithm){
		
		SecretKey secretKey = new SecretKeySpec(key, algorithm);
	    return secretKey;
	}
	
	public static byte[] encrypt(SecretKey key, byte[] data, String algorithmModePadding) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
	BadPaddingException, InvalidAlgorithmParameterException{
		
		String mode = null;
		if(algorithmModePadding.contains("/")){
			 mode = algorithmModePadding.split("/")[1];
		}else{
			mode = algorithmModePadding;
		}
		
		if(mode.equalsIgnoreCase("ECB") ||
				mode.equalsIgnoreCase("ARCFOUR")){
			
			Cipher cipher = Cipher.getInstance(algorithmModePadding);
			cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());
			return cipher.doFinal(data);
			
		}else if(mode.equalsIgnoreCase("CBC") || 
				mode.equalsIgnoreCase("CFB")  ||
				mode.equalsIgnoreCase("CTR")  ||
				mode.equalsIgnoreCase("OFB")  ||
				mode.equalsIgnoreCase("PCBC") ){
			
			Cipher cipher = Cipher.getInstance(algorithmModePadding);
			
			initializationVector = generateIVParameter(cipher.getBlockSize());
			cipher.init(Cipher.ENCRYPT_MODE, key, initializationVector, new SecureRandom());
			
			return cipher.doFinal(data);
		}else{
			System.err.println("NOT SUPPORT " + mode.split("/")[1] + " mode");
			return null;
		}
	}
	
	
	public static byte[] decrypt(SecretKey key, byte[] data, String algorithmModePadding) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		String mode = null;
		if(algorithmModePadding.contains("/")){
			 mode = algorithmModePadding.split("/")[1];
		}else{
			mode = algorithmModePadding;
		}
		
		if(mode.equalsIgnoreCase("ECB") ||
				mode.equalsIgnoreCase("ARCFOUR")){
			
			Cipher cipher = Cipher.getInstance(algorithmModePadding);
			cipher.init(Cipher.DECRYPT_MODE, key, new SecureRandom());
			return cipher.doFinal(data);
			
		}else{
			System.err.println("NOT SUPPORT " + mode.split("/")[1] + " mode");
			return null;
		}
	}
	
	public static byte[] decrypt(SecretKey key, byte[] data, String algorithmModePadding, IvParameterSpec ivParameterSpec) throws 
	NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
	BadPaddingException, InvalidAlgorithmParameterException{
		
		String mode = algorithmModePadding.split("/")[1];
		
		if(mode.equalsIgnoreCase("CBC") || 
				mode.equalsIgnoreCase("CFB")  ||
				mode.equalsIgnoreCase("CTR")  ||
				mode.equalsIgnoreCase("OFB")  ||
				mode.equalsIgnoreCase("PCBC")){
			
			Cipher cipher = Cipher.getInstance(algorithmModePadding);
			cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec, new SecureRandom());
			
			return cipher.doFinal(data);
			
		}else{
			System.err.println("NOT SUPPORT " + mode.split("/")[1] + " mode");
			return null;
		}
		
	}
	
	private static IvParameterSpec generateIVParameter(int cipherBlockSize){
		byte[]  ivBytes = new byte[cipherBlockSize];
        new SecureRandom().nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
	}
	
	public static IvParameterSpec getIVparameter(){
		return initializationVector;
	}
}
