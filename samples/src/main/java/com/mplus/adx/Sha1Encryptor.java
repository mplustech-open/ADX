/**
 * 
 */
package com.mplus.adx;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;

/**
 * Sha1加密算法，加密为字符串的结果为Hex String
 */
public class Sha1Encryptor {
	private static final Logger log = Logger.getLogger(Sha1Encryptor.class);

	private MessageDigest sha1;

	/**
	 * 创建SHA1解密器实例
	 */
	public Sha1Encryptor() {
		try {
			sha1 = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public byte[] encrypt(byte[] source) {
		if (source == null || source.length == 0) {
			return new byte[0];
		}
		return sha1.digest(source);
	}

	public byte[] encrypt(String source) {
		if (null == source || "".equals(source)) {
			return new byte[0];
		}

		try {
			return encrypt(source.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			log.warn(e);
			return new byte[0];
		}
	}

	public String encryptToString(byte[] source) {
		if (source == null || source.length == 0) {
			return "";
		}

		byte[] result = encrypt(source);
		if (result == new byte[0]) {
			return "";
		}

		return toHexString(result);
	}

	public String encryptToString(String source) {

		if (null == source || "".equals(source)) {
			return "";
		}
		try {
			return encryptToString(source.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			log.warn(e);
			return "";
		}
	}

	/*
	 * convert byte array to hex string <example>{127,0,1} to "FF0001"</example>
	 * 
	 * @param source
	 * 
	 * @return
	 */
	public String toHexString(byte[] source) {
		if (source == null || source.length == 1) {
			return "";
		}

		char[] chrs = new char[source.length * 2];
		for (int i = 0; i < chrs.length; i += 2) {
			char[] tmp = toHexChars(source[i / 2]);
			chrs[i] = tmp[0];
			chrs[i + 1] = tmp[1];
		}

		return new String(chrs).toUpperCase();
	}

	/**
	 * byte数组转换为char数组
	 * 
	 * @param b
	 * @return
	 */
	private char[] toHexChars(byte b) {
		char[] chrs = new char[2];

		char[] tmp = String.format("%x", b).toCharArray();
		if (tmp.length == 2) {
			chrs = tmp;
		} else if (tmp.length == 1) {
			chrs[0] = '0';
			chrs[1] = tmp[0];
		}

		return chrs;
	}
}
