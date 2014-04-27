package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

import java.io.Serializable;

public class MessagePayload implements Serializable{

	private static final long serialVersionUID = 5874936569615329921L;
	
	private String fromUci;
	private String toUci;
	
	public MessagePayload(){}
	
	public MessagePayload(String fromUci, String toUci) {
		this.fromUci = fromUci;
		this.toUci = toUci;
	}

	public String getFromUci() {
		return fromUci;
	}

	public void setFromUci(String fromUci) {
		this.fromUci = fromUci;
	}

	public String getToUci() {
		return toUci;
	}

	public void setToUci(String toUci) {
		this.toUci = toUci;
	}
	
	
}
