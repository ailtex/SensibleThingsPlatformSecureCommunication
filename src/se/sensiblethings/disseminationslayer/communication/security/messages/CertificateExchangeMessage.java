package se.sensiblethings.disseminationslayer.communication.security.messages;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CertificateExchangeMessage extends SecureMessage{
		
	/**
	 * 
	 */
	private static final long serialVersionUID = -6311990260314998244L;

	public CertificateExchangeMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		
	}

}
