# SensibleThingsPlatformSecurity
##About
SensibleThings Platform is an open souced platform. It is a platform for enabling the Internet-of-Things. Detail can be found from ShensibleThings Website [ShensibleThings](http://sensiblethings.se)

SensibleThingsPlatformSecurity is one componet under the communication layer in this platfrom. It provides authentication, confidentiality and integrity. In early stage, this platform privoides authentication extension with a pre-shared key to grant access to a specific sensor or actuator.

## Principle



## License
The SensibleThings platform is open source and licensed under the LGPL license. So this part is also under the LGPL license.
This means you can create your own applications (even commercial ones) using the platform.

## Usage
1. Download / Clone this project
2. Download the platfrom fundamental source code from [here](http://sensiblethings.se/files/SensibleThingsPlatformBeta4Source.zip) (2013-10-24 Public Beta 4) 
3. Modify two files:

(1)`se.sensiblethings.disseminationlayer.communication.Communication.java`

Adds set and get functions:

    public HashMap<String, Vector<MessageListener>> getMessageListeners() {
		return messageListeners;
	}
	
	public void setMessageListeners(
			HashMap<String, Vector<MessageListener>> messageListeners) {
		this.messageListeners = messageListeners;
	}
	
Adds one public static string
	
	public final static String SECURITY_COM = "se.sensiblethings.disseminationslayer.communication.security.SecurityCommunication";

(2)`se.sensiblethings.disseminationlayer.communication.Message.java`
Adds two public String variables

	public String fromUci;
	public String toUci;



Finally, At `se.sensiblethings.disseminationslayer.communication.security.test` package, there are three test demos. 

__Remember that bootstrap node shoud always run firtly. And when you change the bootstrap UCI, the configuration file should also have the same modification.__