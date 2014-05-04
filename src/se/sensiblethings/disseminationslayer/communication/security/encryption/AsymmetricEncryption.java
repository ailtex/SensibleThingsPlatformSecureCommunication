package se.sensiblethings.disseminationslayer.communication.security.encryption;

import java.security.Key;   
import java.security.KeyFactory;   
import java.security.KeyPair;   
import java.security.KeyPairGenerator;   
import java.security.NoSuchAlgorithmException;   
import java.security.PrivateKey;   
import java.security.PublicKey;   
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;   
import java.security.spec.PKCS8EncodedKeySpec;   
import java.security.spec.X509EncodedKeySpec;   

import javax.crypto.Cipher;

  
/**
 * AsymmetricEncryption.java
 * 
 * The class implements all functions of asymmetric encryption, including
 * the key pair generation, the key loading from the bytes, the encryption and decryption
 * of the messages, and the out put of the message with hex format
 * 
 * @author Hao
 *
 */
public class AsymmetricEncryption {
	/**
	 * Public key, specify the kind of the key type
	 */
	public static final String PUBLIC_KEY = "PUBLIC";
	/**
	 * Private key, specify the kind of the key type
	 */
	public static final String PRIVATE_KEY = "PRIVATE";
	
	/**
	 * Generate the key pair with specified algorithm, and key length, like ("RSA",1024)
	 * 
	 * @param algorithm The asymmetric encryption algorithm
	 * @param keyLength The key length corresponding to the asymmetric encryption
	 * @return The key pair (public and private key) corresponding to the algorithm
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException {   
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);   
        keyPairGen.initialize(keyLength, new SecureRandom());   
        
        return keyPairGen.generateKeyPair();
    }   
	
	/**
	 * Transform the key from bytes to corresponding instance
	 * 
	 * @param key The key in bytes that will be transformed
	 * @param type The key type : public key ? private key
	 * @param algorithm The key applied in which algorithm
	 * @return The key transformed from the bytes
	 */
	public Key loadKey(byte[] key, String type, String algorithm){   
 
        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance(algorithm);
		 
	        if (type.equals(PRIVATE_KEY)) {    
	            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(key);   
	            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
	            
	            return privateKey;   
	  
	        } else if(type.equals(PUBLIC_KEY)){    
	            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(key);   
	            PublicKey publicKey = keyFactory.generatePublic(bobPubKeySpec);
	            
	            return publicKey;   
	        }
	        
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}   
        return null;
    }  
	
	/**
	 * The encryption operation with specified algorithm
	 * 
	 * @param publicKey The public key that used for this asymmetric encryption
	 * @param data The source message that will be encrypt
	 * @param algorithm The specified asymmetric encryption algorithm
	 * @return the cipher text
	 */
    public static byte[] encrypt(PublicKey publicKey, byte[] data, String algorithm) {   
        if (publicKey != null) {   
            try {  
                Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                return cipher.doFinal(data);
               
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
        return null;   
    }   
    
    /**
     * The decryption operation with specified algorithm
     * 
     * @param privateKey The private key that used for this asymmetric encryption
     * @param raw The cipher text in bytes
     * @param algorithm The specified asymmetric decryption algorithm
     * @return the plain text in bytes
     */
    public static byte[] decrypt(PrivateKey privateKey, byte[] raw, String algorithm) {   
        if (privateKey != null) {   
            try {   
            	Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);   
                
                return cipher.doFinal(raw);   
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
  
        return null;   
    }
	    
    /**
     * Transform the cipher text in bytes to one hex string
     * 
     * @param b the bytes that will be transformed
     * @return the corresponding hex string
     */
    public static String toHexString(byte[] b) {   
        StringBuilder sb = new StringBuilder(b.length * 2);   
        for (int i = 0; i < b.length; i++) {   
            sb.append(HEXCHAR[(b[i] & 0xf0) >>> 4]);   
            sb.append(HEXCHAR[b[i] & 0x0f]);   
        }   
        return sb.toString();   
    }   
    
    /**
     * Transform a string to bytes
     * 
     * @param s the string that will be transformed
     * @return the corresponding bytes
     */
    public static final byte[] toBytes(String s) {   
        byte[] bytes;   
        bytes = new byte[s.length() / 2];   
        for (int i = 0; i < bytes.length; i++) {   
            bytes[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2),   
                    16);   
        }   
        return bytes;   
    }   
  
    private static char[] HEXCHAR = { '0', '1', '2', '3', '4', '5', '6', '7',   
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };  
    
}
