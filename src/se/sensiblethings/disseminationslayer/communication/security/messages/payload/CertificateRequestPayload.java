package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

import org.bouncycastle.jce.PKCS10CertificationRequest;

public class CertificateRequestPayload extends MessagePayload{

	private static final long serialVersionUID = -7246290917557264390L;
	
//	private PKCS10CertificationRequest certRequest = null;
	
	private int nonce;
	
	public CertificateRequestPayload(String fromUci, String toUci){
		super(fromUci, toUci);
	}
//	public PKCS10CertificationRequest getCertRequest() {
//		return certRequest;
//	}
//
//	public void setCertRequest(PKCS10CertificationRequest certRequest) {
//		this.certRequest = certRequest;
//	}
	
	
	public int getNonce() {
		return nonce;
	}

	public void setNonce(int nonce) {
		this.nonce = nonce;
	}

}
