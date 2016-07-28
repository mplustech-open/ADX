package com.mplus.adx;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

public class VastValidator {
	private static Logger log = Logger.getLogger(VastValidator.class);
    private static URL vast3xsdPath = VastValidator.class.getResource("/vast3.xsd");
    private static URL vast4xsdPath = VastValidator.class.getResource("/vast4.xsd");
	
	private static Map<Byte, Validator> xsdValidators = new HashMap<>();
	
	static {
		readXSD();
	}
	
	private static void readXSD() {
		try{
			Validator v3Validator = createValidator(vast3xsdPath.toURI());
			xsdValidators.put((byte)0x03, v3Validator);
			
			Validator v4Validator = createValidator(vast4xsdPath.toURI());
			xsdValidators.put((byte)0x04, v4Validator);
		} catch (SAXException | URISyntaxException e) {
			log.error(String.format("Read Vast XSD error. Path: %s", vast3xsdPath), e);
		}
	}
	
	
	private static Validator createValidator(URI xsdPath) throws SAXException {
		SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = factory.newSchema(new File(xsdPath));
		return schema.newValidator();
	}
	
	public static boolean validate(byte version, String vast) {
		Validator validator = xsdValidators.get(version);
		if (null != validator) {
			try {
				validator.validate(new StreamSource(new StringReader(vast)));
				return true;
			} catch (SAXException | IOException e) {
				log.error(String.format("Validator vast error. version:%s --> vast:%s", version, vast), e);
			}
		}
		return false;
	}
	
	public static boolean validate(byte version, Reader reader) {
		Validator validator = xsdValidators.get(version);
		if (null != validator) {
			try {
				validator.validate(new StreamSource(reader));
				return true;
			} catch (SAXException | IOException e) {
				log.error(String.format("Validator vast error. version:%s, vast:%s", version, reader), e);
			}
		}
		return false;
	}
}
