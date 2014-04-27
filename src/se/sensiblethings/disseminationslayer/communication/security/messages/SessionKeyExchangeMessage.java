package se.sensiblethings.disseminationslayer.communication.security.messages;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SessionKeyExchangeMessage extends SecureMessage{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8794411419942450449L;
		
	private byte[] certificatePayload;
	private byte[] secretKeyPayload;
	
	public SessionKeyExchangeMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
	}

	public byte[] getCertificatePayload() {
		return certificatePayload;
	}

	public void setCertificatePayload(byte[] certificatePayload) {
		this.certificatePayload = certificatePayload;
	}

	public byte[] getSecretKeyPayload() {
		return secretKeyPayload;
	}

	public void setSecretKeyPayload(byte[] secretKeyPayload) {
		this.secretKeyPayload = secretKeyPayload;
	}
	
}
