package se.sensiblethings.disseminationslayer.communication.security.messages;

import se.sensiblethings.disseminationlayer.communication.Message;
import se.sensiblethings.interfacelayer.SensibleThingsNode;

public class CommunicationShiftMessage extends SecureMessage{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7758694573355260412L;
	
	private String signal;
	
	public CommunicationShiftMessage(String toUci, String fromUci, SensibleThingsNode toNode,
			SensibleThingsNode fromNode) {
		super(toUci, fromUci, toNode, fromNode);
	}

	public String getSignal() {
		return signal;
	}

	public void setSignal(String signal) {
		this.signal = signal;
	}
	
	
}
