package se.sensiblethings.disseminationslayer.communication.security.messages;

import java.security.cert.Certificate;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationResponseMessage extends SecureMessage{


	private static final long serialVersionUID = -455090768499986394L;
	private Certificate cert;

	public RegistrationResponseMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);

	}

	public Certificate getCertificate() {
		return cert;
	}

	public void setCertificate(Certificate cert) {
		this.cert = cert;
	}
	
}
