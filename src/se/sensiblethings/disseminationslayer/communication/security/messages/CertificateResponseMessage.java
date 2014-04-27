package se.sensiblethings.disseminationslayer.communication.security.messages;


import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateResponseMessage extends SecureMessage{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 6156947343675430146L;

	// contain the session symmetric key encrypt by the public key of applicant
	private byte[] encryptSecretKey = null;
	
	public CertificateResponseMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		
	}

	public byte[] getEncryptSecretKey() {
		return encryptSecretKey;
	}

	public void setEncryptSecretKey(byte[] encryptSecretKey) {
		this.encryptSecretKey = encryptSecretKey;
	}

}
