package se.sensiblethings.disseminationslayer.communication.security.messages;

import java.security.cert.Certificate;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateExchangeResponseMessage extends SecureMessage{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -4978617651995412001L;
	
	private Certificate cert;
	
	// Below two are encrypt by RSA
	private byte[] uci = null;
	
	public CertificateExchangeResponseMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
	}

	public Certificate getCert() {
		return cert;
	}

	public void setCert(Certificate cert) {
		this.cert = cert;
	}

	public byte[] getUci() {
		return uci;
	}

	public void setUci(byte[] uci) {
		this.uci = uci;
	}

	
}
