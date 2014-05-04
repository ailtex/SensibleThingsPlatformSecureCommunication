package se.sensiblethings.disseminationslayer.communication.security.messages;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateRequestMessage extends SecureMessage{

	private static final long serialVersionUID = -3858164569571353606L;
	
	private byte[] certRequest = null;
	
	// Below two are encrypt by RSA
	private byte[] nonce = null;
	private byte[] uci = null;
	
	public CertificateRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		
		super(toUci, fromUci, toNode, fromNode);
		
	}
	
	public byte[] getCertRequestDEREncoded() {
		return certRequest;
	}

	public void setCertRequest(byte[] certRequest) {
		this.certRequest = certRequest;
	}
	
	public void setCertRequest(PKCS10CertificationRequest certRequest){
		this.certRequest = certRequest.getEncoded();
	}
	
	public PKCS10CertificationRequest getCertRequest(){
		return new PKCS10CertificationRequest(certRequest);
	}

	public byte[] getNonce() {
		return nonce;
	}

	public void setNonce(byte[] nonce) {
		this.nonce = nonce;
	}

	public byte[] getUci() {
		return uci;
	}

	public void setUci(byte[] Uci) {
		this.uci = Uci;
	}
	
}
