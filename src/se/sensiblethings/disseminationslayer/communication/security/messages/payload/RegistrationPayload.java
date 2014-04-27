package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

public class RegistrationPayload extends MessagePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = -6081566684240037641L;
	
	private long timeStamp;
	
	public RegistrationPayload(String fromUci, String toUci){
		super(fromUci, toUci);
	}
	
	public void setTimeStamp(long timeStamp){
		this.timeStamp = timeStamp;
	}
}
