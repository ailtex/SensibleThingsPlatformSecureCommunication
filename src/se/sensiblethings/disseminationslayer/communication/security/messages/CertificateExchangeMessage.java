package se.sensiblethings.disseminationslayer.communication.security.messages;

import java.util.Date;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateExchangeMessage extends SecureMessage{
		
	public CertificateExchangeMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		
	}

}
