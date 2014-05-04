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

/**
 * SymmetricEncryption.java
 * 
 * This class implements all functions about symmetric en/de-cryption,
 * with different algorithm and modes. There are four symmetric algorithms, AES, DES, DESede and RC4.
 * DES is not strong enough the anti the attack. Only other three are suggested. </p>
 * To corresponding block ciphers, there are many kinds of modes that could be chosen, including CBC,
 * ECB, CFB, OFB, PCBC and CTR. Considering the security, ECB is not suggested, except for small block
 * encryption, like for the key. Finally, the padding mode is the same to all of them, PKCS5Padding. 
 * 
 * @author Hao
 *
 */
public class SymmetricEncryption {
	
	/**
	 * The AES algorithm
	 */
	public static final String AES = "AES";
	/**
	 * The DES algorithm
	 */
	public static final String DES = "DES";
	/**
	 * The DES3 algorithm
	 */
	public static final String DESede = "DESede";
	/**
	 * The RC4 algorithm
	 */
	public static final String RC4 = "ARCFOUR";
	
	/**
	 * A DES cipher with ECB mode and PKCS5Padding
	 */
	public static final String DES_ECB_PKCS5 = "DES/ECB/PKCS5Padding";
	/**
	 * A DES cipher with CBC mode and PKCS5Padding
	 */
	public static final String DES_CBC_PKCS5 = "DES/CBC/PKCS5Padding";
	/**
	 * A DES3 cipher with CBC mode and PKCS5Padding
	 */
	public static final String DESede_CBC_PKCS5 = "DESede/CBC/PKCS5Padding";
	/**
	 * A DES3 cipher with ECB mode and PKCS5Padding
	 */
	public static final String DESede_ECB_PKCS5 = "DESede/ECB/PKCS5Padding";
	/**
	 * An AES cipher with CBC mode and PKCS5Padding
	 */
	public static final String AES_CBC_PKCS5 = "AES/CBC/PKCS5Padding";
	/**
	 * An AES cipher with ECB mode and PKCS5Padding
	 */
	public static final String AES_ECB_PKCS5 = "AES/ECB/PKCS5Padding";
	/**
	 * An AES cipher with CFB mode and PKCS5Padding
	 */
	public static final String AES_CFB_PKCS5 = "AES/CFB/PKCS5Padding";
	/**
	 * An AES cipher with OFB mode and PKCS5Padding
	 */
	public static final String AES_OFB_PKCS5 = "AES/OFB/PKCS5Padding";
	/**
	 * An AES cipher with PCBC mode and PKCS5Padding
	 */
	public static final String AES_PCBC_PKCS5 = "AES/PCBC/PKCS5Padding";
	/**
	 * An AES cipher with CTR mode and PKCS5Padding
	 */
	public static final String AES_CTR_PKCS5 = "AES/CTR/PKCS5Padding";
	
	// The initialization vector that used in block ciphers modes except ECB
	private static IvParameterSpec initializationVector = null;
	
	/**
	 * Generate the secret key with specified algorithm and key length
	 * 
	 * @param algorithm The specified symmetric en/de-cryption algorithm
	 * @param keyLength The key length
	 * @return The secret key
	 * @throws NoSuchAlgorithmException the algorithm are not supported
	 */
	public static SecretKey generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException{
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(keyLength, new SecureRandom());
		return keyGenerator.generateKey();
	}
	
	/**
	 * Load the key from bytes, or it transforms the key from bytes to the instance
	 * 
	 * @param key the key bytes
	 * @param algorithm the specified algorithm corresponding to this key
	 * @return The key transformed or loaded from the bytes
	 */
	public static Key loadKey(byte[] key, String algorithm){
		SecretKey secretKey = new SecretKeySpec(key, algorithm);
	    return secretKey;
	}
	
	/**
	 * The symmetric encrypt operation with specified mode
	 * 
	 * ECB, and RC4 do not need initialization vector(IV). When anyone of CBC, CFB, CTR, OFB, and PCBC is applied,
	 * an initialization vector will be generated. The IV will be used only once to each message.
	 * 
	 * @param key The secret key to encrypt the message
	 * @param data The plain text in bytes that will be encrypt
	 * @param algorithmModePadding Specified algorithm/mode/padding for this encryption
	 * @return The cipher text in bytes
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
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
	
	/**
	 * The decryption operation with specified algorithm/mode/padding
	 * 
	 * This decryption operation only support for ECB mode and RC4 algorithm, as they do not need
	 * initialization vector.
	 * 
	 * @param key The secret key to decrypt the message
	 * @param data The cipher text
	 * @param algorithmModePadding Specified algorithm/mode/padding for this decryption
	 * @return The plain text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
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
	
	/**
	 * The decryption operation with specified algorithm/mode/padding
	 * 
	 * This decryption operation supports those modes that needs initialization verctor.
	 *  
	 * @param key The secret key to decrypt the message
	 * @param data The cipher text
	 * @param algorithmModePadding Specified algorithm/mode/padding for this decryption
	 * @param ivParameterSpec The initialization verctor
	 * @return The plain text
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
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
	
	/**
	 * Generate the initialization vector
	 * 
	 * @param cipherBlockSize the block size of specified cipher
	 * @return the initialization vector
	 */
	private static IvParameterSpec generateIVParameter(int cipherBlockSize){
		byte[]  ivBytes = new byte[cipherBlockSize];
        new SecureRandom().nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
	}
	
	/**
	 * Get the initialization vector
	 * @return
	 */
	public static IvParameterSpec getIVparameter(){
		return initializationVector;
	}
}
