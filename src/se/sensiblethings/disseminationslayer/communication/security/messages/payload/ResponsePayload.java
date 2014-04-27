package se.sensiblethings.disseminationslayer.communication.security.messages.payload;

public class ResponsePayload extends MessagePayload{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6032299179015406951L;
	
	private int fromNonce;
	private int toNonce;
	
	
	public ResponsePayload(String fromUci, String toUci){
		super(fromUci, toUci);
	}
	
	public int getFromNonce() {
		return fromNonce;
	}
	public void setFromNonce(int fromNonce) {
		this.fromNonce = fromNonce;
	}
	public int getToNonce() {
		return toNonce;
	}
	public void setToNonce(int toNonce) {
		this.toNonce = toNonce;
	}

}
