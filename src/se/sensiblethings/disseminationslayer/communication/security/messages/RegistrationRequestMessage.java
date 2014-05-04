package se.sensiblethings.disseminationslayer.communication.security.messages;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class RegistrationRequestMessage extends SecureMessage{

	private static final long serialVersionUID = -7196963283243573690L;
	
	public RegistrationRequestMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode){
		super(toUci, fromUci, toNode, fromNode);

	}
	
}
