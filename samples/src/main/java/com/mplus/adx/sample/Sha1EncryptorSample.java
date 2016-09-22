package com.mplus.adx.sample;

import com.mplus.adx.Sha1Encryptor;

public class Sha1EncryptorSample {
	public static void main(String[] args) {
		String clientKey = "7CE167C1778E4A21BF7C1A1D80C1E8BF";
		int timestamp = 1460966991;

		String source = String.format("%s|%s", clientKey, timestamp);
		String encryptStr = new Sha1Encryptor().encryptToString(source);

		System.out.println(encryptStr);
	}
}
