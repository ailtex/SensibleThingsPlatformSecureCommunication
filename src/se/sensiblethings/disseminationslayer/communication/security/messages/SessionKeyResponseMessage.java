package se.sensiblethings.disseminationslayer.communication.security.messages;

import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class SessionKeyResponseMessage extends SecureMessage{

	/**
	 * 
	 */
	private static final long serialVersionUID = 8306476604080827400L;

	public SessionKeyResponseMessage(String toUci, String fromUci,
			SensibleThingsNode toNode, SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
		// TODO Auto-generated constructor stub
	}

}
