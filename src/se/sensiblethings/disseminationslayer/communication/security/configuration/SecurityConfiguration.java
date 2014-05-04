package se.sensiblethings.disseminationslayer.communication.security.configuration;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.commons.configuration.reloading.ReloadingStrategy;
import org.apache.commons.configuration.tree.xpath.XPathExpressionEngine;

/**
 * SecurityConfiguration.java
 * 
 * This class read the XML format configuration file, and refresh the context with 5s.
 * It provides parameters that this system needed, corresponding the specified security level
 * 
 * @author Hao
 *
 */
public class SecurityConfiguration {
	
	private int securityLevel;
	private XMLConfiguration config = null;
	
	/**
	 * The interval time between each context refresh
	 */
	public static final long REFRESH_INTERVAL = 5000;
	
	/**
	 * Load the configuration file, and set the reloading strategy to refresh the context 
	 * in every certain time;
	 * 
	 * @param filePath The path of the configuration file
	 * @param securityLevel The security level that should be initially specified
	 */
	public SecurityConfiguration(String filePath, int securityLevel){
		this.securityLevel = securityLevel;
		
		try {
			config =new XMLConfiguration(filePath);
			config.setExpressionEngine(new XPathExpressionEngine());
			
			// reloading strategy for this configuration every 5s
			ReloadingStrategy strategy =new FileChangedReloadingStrategy();
			((FileChangedReloadingStrategy) strategy).setRefreshDelay(REFRESH_INTERVAL);
			config.setReloadingStrategy(strategy);

		} catch (ConfigurationException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Set the security level
	 * @param securityLevel The security level that should be set
	 */
	public void setSecurityLevel(int securityLevel) {
		this.securityLevel = securityLevel;
	}
	
	/**
	 * Get the security level
	 * @return Current security Level
	 */
	public int getSecurityLevel() {
		return securityLevel;
	}
	
	/**
	 * Get the Bootstrap UCI
	 * @return The Bootstrap UCI
	 */
	public String getBootstrapUci(){
		return config.getString("/bootstrap/uci");
	}
	
	/**
	 * Get the Bootstrap IP
	 * @return  The Bootstrap IP
	 */
	public String getBootstrapIP(){
		return config.getString("/bootstrap/ip");
	}
	
	/**
	 * Get the Bootstrap Port
	 * @return The Bootstrap Port
	 */
	public String getBootstrapPort(){
		return config.getString("/bootstrap/port");
	}
	
	/**
	 * Get the key store file name
	 * @return The key store file name
	 */
	public String getKeyStoreFileName(){
		return config.getString("/keyStore/name");
	}
	
	/**
	 * Get the directory of the key store file
	 * @return The directory of the key store file
	 */
	public String getKeyStoreFileDirectory(){
		return config.getString("/keyStore/directory");
	}
	
	/**
	 * Get the symmetric algorithm name with specified security level
	 * @return The symmetric algorithm name with specified security level
	 */
	public String getSymmetricAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/algorithm" );
	}
	
	/**
	 * Get the symmetric encryption mode with specified security level
	 * @return The symmetric encryption mode with specified security level
	 */
	public String getSymmetricMode(){
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/mode" );
	}
	/**
	 * Get the key length of the symmetric key with specified security level
	 * @return The symmetric key length with specified security level
	 */
	public int getSymmetricKeyLength() {
		return config.getInt("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/key/length");
	}
	/**
	 * Get the life time of the symmetric key  with specified security level
	 * @return The life time of the symmetric key  with specified security level
	 */ 
	public long getSymmetricKeyLifeTime() {
		return config.getLong("/security[level='" + String.valueOf(securityLevel) + "']/symmetric/key/lifetime");
	}
	/**
	 * Get the asymmetric algorithm name with specified security level
	 * @return The asymmetric algorithm name with specified security level
	 */
	public String getAsymmetricAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/algorithm" );
	}
	/**
	 * Get the key length of the asymmetric key with specified security level
	 * @return The key length of the asymmetric key with specified security level
	 */
	public int getAsymmetricKeyLength() {
		return config.getInt("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/key/length");
	}
	/**
	 * Get the life time of the asymmetric key  with specified security level
	 * @return The life time of the asymmetric key  with specified security level
	 */
	public long getAsymmetricKeyLifetime() {
		return config.getLong("/security[level='" + String.valueOf(securityLevel) + "']/asymmetric/key/lifetime");
	}
	/**
	 * Get the signature algorithm with the specified security level
	 * @return The signature algorithm with the specified security level
	 */
	public String getSignatureAlgorithm() {
		return config.getString("/security[level='" + String.valueOf(securityLevel) + "']/signature/algorithm" );
	}

	

}
