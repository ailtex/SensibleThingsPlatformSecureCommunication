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

import org.apache.commons.lang.ArrayUtils;

  

public class AsymmetricEncryption {
	
	public static final String publicKey = "PUBLIC";
	public static final String privateKey = "PRIVATE";
	
	public static KeyPair generateKey(String algorithm, int keyLength) throws NoSuchAlgorithmException {   
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);   
        keyPairGen.initialize(keyLength, new SecureRandom());   
        
        return keyPairGen.generateKeyPair();
    }   
	
	public Key loadKey(byte[] key, String type, String algorithm){   
 
        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance(algorithm);
		 
	        if (type.equals(privateKey)) {    
	            PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(key);   
	            PrivateKey privateKey = keyFactory.generatePrivate(priPKCS8);
	            
	            return privateKey;   
	  
	        } else if(type.equals(publicKey)){    
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
     * 
     * @param publicKey
     * @param data
     * @return
     */
    public static byte[] encrypt(PublicKey publicKey, byte[] data, String algorithm) {   
        if (publicKey != null) {   
            try {   
            	//if(algorithm.equals("RSA")) algorithm = "RSA/ECB/PKCS1Padding";
            	
                Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                return cipher.doFinal(data);
               
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
        return null;   
    }   
    

    public static byte[] decrypt(PrivateKey privateKey, byte[] raw, String algorithm) {   
        if (privateKey != null) {   
            try {   
            	//if(algorithm.equals("RSA")) algorithm = "RSA/ECB/PKCS1Padding";
            	
            	Cipher cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);   
                
                return cipher.doFinal(raw);   
            } catch (Exception e) {   
                e.printStackTrace();   
            }   
        }   
  
        return null;   
    }
	    
      
    public static String toHexString(byte[] b) {   
        StringBuilder sb = new StringBuilder(b.length * 2);   
        for (int i = 0; i < b.length; i++) {   
            sb.append(HEXCHAR[(b[i] & 0xf0) >>> 4]);   
            sb.append(HEXCHAR[b[i] & 0x0f]);   
        }   
        return sb.toString();   
    }   
  
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
