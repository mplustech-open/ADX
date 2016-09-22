package com.mplus.adx.sample;

import static org.junit.Assert.assertEquals;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.mplus.adx.PriceCryptor;
import com.mplus.adx.PriceCryptor.Keys;
import com.mplus.adx.PriceCryptor.PriceInfo;

public class PriceCryptorSample {
	private static final String EncryptionKey = "77165979f11b497da6f81b3bb320932c";
	private static final String IntegrityKey = "f9db51664f8a44f99ef08b17f6c11ab3";

	public static void main(String[] args) {
		long price = 12345l;
		long time = 1464838032123l;
		long serverId = 29235l;

		try {
			// step1: init keys
			SecretKey eKey = new SecretKeySpec(EncryptionKey.getBytes(), "HmacSHA1");
			SecretKey iKey = new SecretKeySpec(IntegrityKey.getBytes(), "HmacSHA1");
			Keys keys = new Keys(eKey, iKey);

			// step2: new PriceCryptor
			PriceCryptor cryptor = new PriceCryptor(keys);
			// step3: encrypt price
			PriceInfo priceInfo = new PriceInfo(price, time, serverId);
			String encryptPriceStr = cryptor.encryptPrice(priceInfo);
			assertEquals("AAABVQ8mivsAAAAAAAByM5nk4xXcVyW_We11ig==", encryptPriceStr);

			// step4: decrypt price
			PriceInfo dpriceInfo = cryptor.decryptPrice(encryptPriceStr);
			assertEquals(serverId, dpriceInfo.getServerId());
			assertEquals(time, dpriceInfo.getCurrentTimeMillis());
			assertEquals(price, dpriceInfo.getPrice());

			System.out.println(encryptPriceStr);
		} catch (InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
	}
}
