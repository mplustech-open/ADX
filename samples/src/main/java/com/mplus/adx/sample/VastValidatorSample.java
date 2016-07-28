package com.mplus.adx.sample;

import static org.junit.Assert.assertTrue;

import java.io.File;

import com.mplus.adx.FileHelper;
import com.mplus.adx.VastValidator;

public class VastValidatorSample {
	private static String basePath = VastValidatorSample.class.getClassLoader().getResource("").getPath()
			+ File.separator;

	public static void main(String[] args) {
		String vast = readVastXml(basePath + "vast4-ad1.xml");
		boolean result = VastValidator.validate((byte)0x04, vast);
		assertTrue(result);
		
		vast = readVastXml(basePath + "vast4-ad2.xml");
		result = VastValidator.validate((byte)0x04, vast);
		assertTrue(result);
		
		System.out.println("Vast xml pass validate.");
	}
	
	private static String readVastXml(String path) {
		try {
			return new String(FileHelper.readBytes(path));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
