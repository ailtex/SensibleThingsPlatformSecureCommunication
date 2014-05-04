package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

public class CertificateExchangePayload extends CertificatePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = 129596739686835045L;
	
	private long timeStamp;
	
	public CertificateExchangePayload(String fromUci, String toUci) {
		super(fromUci, toUci);
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setTimeStamp(long timeStamp) {
		this.timeStamp = timeStamp;
	}
	
}
