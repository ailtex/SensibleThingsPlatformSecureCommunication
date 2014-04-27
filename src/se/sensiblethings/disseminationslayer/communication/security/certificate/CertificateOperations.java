package se.sensiblethings.disseminationslayer.communication.security.certificate;

/*
 * This part is about the certificate operations with Bouncy Castle APIs
 * Here is one document about this part : 
 * http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
 * 
 */

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;


public class CertificateOperations {
	
	private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
	/**
	 * There is one solution to generate the X509 certificate without using the Bouncy Castle
	 * Detail can be found from below (Actually it's similar to doSelfCert from the keytool souce code):</p>
	 * 1, http://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle</p>
	 * 2, http://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate.html
	 * While sun.security.* package is required which has some contradiction with support/ stable principle
	 * So here decide to use Bouncy Castle to implement this
	 * 
	 * @param certificate
	 * @return 
	 */
	@SuppressWarnings("deprecation")
	public static X509Certificate generateSelfSignedcertificate(String subjectName, KeyPair keyPair, long lifeTime){
		
		// add BouncyCastal to the security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		X509Certificate cert = null;
		
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		
		// The specification of X.500 distinguished name
		// C Country
		// CN Common name
		// DC Domain component
		// E E-mail address
		// EMAIL E-mail address (preferred)
		// EMAILADDRESS E-mail address
		// L Locality
		// O Organization name
		// OU Organizational unit name
		// PC Postal code
		// S State or province
		// SN Family name
		// SP State or province
		// ST State or province (preferred)
		// STREET Street
		// T Title
		// 

		if(subjectName == null)
			subjectName = "CN="+ subjectName + ",OU=ComputerColleage,O=MIUN,C=Sweden";

		certGen.setIssuerDN(new X500Principal(subjectName));
		
	    certGen.setNotBefore(new Date(System.currentTimeMillis() )); // time from which certificate is valid
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + lifeTime));  // time after which certificate is not valid
	    
	    certGen.setSubjectDN(new X500Principal(subjectName));
	    certGen.setPublicKey(keyPair.getPublic());
	    certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM);
	    
	    try {
			cert = certGen.generateX509Certificate(keyPair.getPrivate(), "BC");
		} catch (InvalidKeyException | NoSuchProviderException
				| SecurityException | SignatureException e) {
			
			e.printStackTrace();
		}
	    
	    return cert;
	}
	
	
	@SuppressWarnings({ "deprecation", "unchecked" })
	public static PKCS10CertificationRequest generateCertificateSigningRequest(String subjectName, KeyPair keyPair){
		// add BouncyCastal to the security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		X500Principal sn = new X500Principal(subjectName);
		
		// Creation of the extensionRequest attribute 
		// Including an email address in the SubjectAlternative name extension
		// create the extension value
		GeneralNames subjectAltName = new GeneralNames(
		                   new GeneralName(GeneralName.rfc822Name, subjectName));

		// create the extensions object and add it as an attribute
		Vector oids = new Vector();
		Vector values = new Vector();

		oids.add(X509Extensions.SubjectAlternativeName);
		try {
			values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
		} catch (IOException e1) {
			
			e1.printStackTrace();
		}
		
		// adding extra extensions to the certification request is 
		// just a matter of adding extra oids and extension objects to the oids 
		// and values Vector objects respectively
		
		X509Extensions extensions = new X509Extensions(oids, values);

		Attribute attribute = new Attribute(
		                           PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
		                           new DERSet(extensions));
		
		try {
			return new PKCS10CertificationRequest(
			          "SHA256withRSA",
			          sn,
			          keyPair.getPublic(),
			          new DERSet(attribute),    // wrapping it in an ASN.1 SET
			          keyPair.getPrivate());
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchProviderException | SignatureException e) {
			
			e.printStackTrace();
		}
		return null;
	}
	
	@SuppressWarnings("deprecation")
	public static X509Certificate[] buildChain(PKCS10CertificationRequest request, X509Certificate rootCert, KeyPair rootPair, long lifeTime) throws
	InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, CertificateParsingException{
		
		// add BouncyCastal to the security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		// validate the certification request
		if (!request.verify("BC")) {
			System.out.println("request failed to verify!");
			System.exit(1);
		}
		
		// create the certificate using the information in the request
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(rootCert.getSubjectX500Principal());
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + lifeTime));
		certGen.setSubjectDN(new X500Principal(request.getCertificationRequestInfo().getSubject().toString()));
		certGen.setPublicKey(request.getPublicKey("BC"));
		certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM);

		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				new AuthorityKeyIdentifierStructure(rootCert));

		certGen.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));

		certGen.addExtension(X509Extensions.BasicConstraints, true,
				new BasicConstraints(false));

		certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(
				KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

		certGen.addExtension(X509Extensions.ExtendedKeyUsage, true,
				new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		// extract the extension request attribute
		ASN1Set attributes = request.getCertificationRequestInfo()
				.getAttributes();

		for (int i = 0; i != attributes.size(); i++) {
			Attribute attr = Attribute.getInstance(attributes.getObjectAt(i));

			// process extension request
			if (attr.getAttrType().equals(
					PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				X509Extensions extensions = X509Extensions.getInstance(attr
						.getAttrValues().getObjectAt(0));

				Enumeration e = extensions.oids();
				while (e.hasMoreElements()) {
					DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
					X509Extension ext = extensions.getExtension(oid);

					certGen.addExtension(oid, ext.isCritical(), ext.getValue()
							.getOctets());
				}
			}
		}
		X509Certificate issuedCert = certGen.generateX509Certificate(rootPair.getPrivate());

		return new X509Certificate[] { issuedCert, rootCert };
	}
	
	/**
	 * For certificates, the available formats are PEM, DER and PKCS12 
	 * In general, the PEM formats are mostly used in the Unix world, 
	 * PCKS12 in the Microsoft world and DER in the Java world.
	 * 
	 * @param cert
	 */
	public void standOutInPemEncoded(X509Certificate cert){
		PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out));
		try {
			pemWrt.writeObject(cert);
			pemWrt.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
}
