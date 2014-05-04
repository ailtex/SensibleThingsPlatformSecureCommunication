package se.sensiblethings.disseminationslayer.communication.security.messages.payload;


public class SecretKeyPayload extends MessagePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = 8845829119915708208L;
	
//	private SecretKey key = null;
//	private String algorithm = null;
//	private long lifeTime;	
	private int nonce;
	
	public SecretKeyPayload(String fromUci, String toUci) {
		super(fromUci, toUci);
	}


//	public SecretKey getKey() {
//		return key;
//	}
//
//
//	public void setKey(SecretKey key) {
//		this.key = key;
//	}
//
//
//	public String getAlgorithm() {
//		return algorithm;
//	}
//
//
//	public void setAlgorithm(String algorithm) {
//		this.algorithm = algorithm;
//	}
//
//
//	public long getLifeTime() {
//		return lifeTime;
//	}
//
//
//	public void setLifeTime(long lifeTime) {
//		this.lifeTime = lifeTime;
//	}
	
	public int getNonce() {
		return nonce;
	}

	public void setNonce(int nonce) {
		this.nonce = nonce;
	}

}
