package com.mplus.adx;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static java.lang.Math.min;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import org.apache.log4j.Logger;

import com.google.common.base.MoreObjects;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Ints;

/**
 * from DoubleClickCrypto
 * 
 * @see https://github.com/google/openrtb-doubleclick
 * @author bill.huang
 *
 */
public class PriceCryptor {
	private static Logger logger = Logger.getLogger(PriceCryptor.class);

	public static final String KEY_ALGORITHM = "HmacSHA1";

	/** Initialization vector offset in the crypto package. */
	public static final int INITV_BASE = 0;
	/** Initialization vector size. */
	public static final int INITV_SIZE = 16;
	/** Timestamp subfield offset in the initialization vector. */
	public static final int INITV_TIMESTAMP_OFFSET = 0;
	/** ServerId subfield offset in the initialization vector. */
	public static final int INITV_SERVERID_OFFSET = 8;
	/** Payload offset in the crypto package. */
	public static final int PAYLOAD_BASE = INITV_BASE + INITV_SIZE;
	/** Integrity signature size. */
	public static final int SIGNATURE_SIZE = 4;
	/** Overhead (non-Payload data) total size. */
	public static final int OVERHEAD_SIZE = INITV_SIZE + SIGNATURE_SIZE;

	private static final int COUNTER_PAGESIZE = 20;
	private static final int COUNTER_SECTIONS = 3 * 256 + 1;

	private static final int MICROS_PER_CURRENCY_UNIT = 1_000_000;

	private static final int PAYLOAD_SIZE = 8;

	private static final ThreadLocalRandom fastRandom = ThreadLocalRandom.current();
	private final Keys keys;

	public PriceCryptor(Keys keys) {
		this.keys = keys;
	}

	public String encryptPrice(PriceInfo priceInfo) {
		return encodePriceMicros(priceInfo.getPrice(),
				createInitVector(new Date(priceInfo.getCurrentTimeMillis()), priceInfo.getServerId()));
	}

	public PriceInfo decryptPrice(String encryptPriceStr) throws SignatureException {
		byte[] deBytes = decrypt(decode(encryptPriceStr));

		ByteBuffer buffer = ByteBuffer.wrap(deBytes);
		long time = buffer.getLong();
		long serverId = buffer.getLong();
		long price = buffer.getLong();
		
		return new PriceInfo(price, time, serverId);
	}

	/**
	 * Decrypts data.
	 *
	 * @param cipherData
	 *            {@code initVector || E(payload) || I(signature)}
	 * @return {@code initVector || payload || I'(signature)} Where
	 *         I'(signature) == I(signature) for success, different for failure
	 */
	public byte[] decrypt(byte[] cipherData) throws SignatureException {
		checkArgument(cipherData.length >= OVERHEAD_SIZE, "Invalid cipherData, %s bytes", cipherData.length);

		// workBytes := initVector || E(payload) || I(signature)
		byte[] workBytes = cipherData.clone();
		ByteBuffer workBuffer = ByteBuffer.wrap(workBytes);
		boolean success = false;

		try {
			// workBytes := initVector || payload || I(signature)
			xorPayloadToHmacPad(workBytes);
			// workBytes := initVector || payload || I'(signature)
			int confirmationSignature = hmacSignature(workBytes);
			int integritySignature = workBuffer.getInt(workBytes.length - SIGNATURE_SIZE);
			workBuffer.putInt(workBytes.length - SIGNATURE_SIZE, confirmationSignature);

			if (confirmationSignature != integritySignature) {
				throw new SignatureException("Signature mismatch: " + Integer.toHexString(confirmationSignature)
						+ " vs " + Integer.toHexString(integritySignature));
			}

			if (logger.isDebugEnabled()) {
				logger.debug(dump("Decrypted", cipherData, workBytes));
			}

			success = true;
			return workBytes;
		} finally {
			if (!success && logger.isDebugEnabled()) {
				logger.debug(dump("Decrypted (failed)", cipherData, workBytes));
			}
		}
	}

	/**
	 * Encrypts data.
	 *
	 * @param plainData
	 *            {@code initVector || payload || zeros:4}
	 * @return {@code initVector || E(payload) || I(signature)}
	 */
	public byte[] encrypt(byte[] plainData) {
		checkArgument(plainData.length >= OVERHEAD_SIZE, "Invalid plainData, %s bytes", plainData.length);

		// workBytes := initVector || payload || zeros:4
		byte[] workBytes = plainData.clone();
		ByteBuffer workBuffer = ByteBuffer.wrap(workBytes);
		boolean success = false;

		try {
			// workBytes := initVector || payload || I(signature)
			int signature = hmacSignature(workBytes);
			workBuffer.putInt(workBytes.length - SIGNATURE_SIZE, signature);
			// workBytes := initVector || E(payload) || I(signature)
			xorPayloadToHmacPad(workBytes);

			if (logger.isDebugEnabled()) {
				logger.debug(dump("Encrypted", plainData, workBytes));
			}

			success = true;
			return workBytes;
		} finally {
			if (!success && logger.isDebugEnabled()) {
				logger.debug(dump("Encrypted (failed)", plainData, workBytes));
			}
		}
	}

	/**
	 * {@code payload = payload ^ hmac(encryptionKey, initVector || counterBytes)}
	 * per max-20-byte blocks.
	 */
	private void xorPayloadToHmacPad(byte[] workBytes) {
		int payloadSize = workBytes.length - OVERHEAD_SIZE;
		int sections = (payloadSize + COUNTER_PAGESIZE - 1) / COUNTER_PAGESIZE;
		checkArgument(sections <= COUNTER_SECTIONS, "Payload is %s bytes, exceeds limit of %s", payloadSize,
				COUNTER_PAGESIZE * COUNTER_SECTIONS);

		Mac encryptionHmac = createMac();

		byte[] pad = new byte[COUNTER_PAGESIZE + 3];
		int counterSize = 0;

		for (int section = 0; section < sections; ++section) {
			int sectionBase = section * COUNTER_PAGESIZE;
			int sectionSize = min(payloadSize - sectionBase, COUNTER_PAGESIZE);

			try {
				encryptionHmac.reset();
				encryptionHmac.init(keys.getEncryptionKey());
				encryptionHmac.update(workBytes, INITV_BASE, INITV_SIZE);
				if (counterSize != 0) {
					encryptionHmac.update(pad, COUNTER_PAGESIZE, counterSize);
				}
				encryptionHmac.doFinal(pad, 0);
			} catch (ShortBufferException | InvalidKeyException e) {
				throw new IllegalStateException(e);
			}

			for (int i = 0; i < sectionSize; ++i) {
				workBytes[PAYLOAD_BASE + sectionBase + i] ^= pad[i];
			}

			Arrays.fill(pad, 0, COUNTER_PAGESIZE, (byte) 0);

			if (counterSize == 0 || ++pad[COUNTER_PAGESIZE + counterSize - 1] == 0) {
				++counterSize;
			}
		}
	}

	/**
	 * {@code signature = hmac(integrityKey, payload || initVector)}
	 */
	private int hmacSignature(byte[] workBytes) {
		try {
			Mac integrityHmac = createMac();
			integrityHmac.init(keys.getIntegrityKey());
			integrityHmac.update(workBytes, PAYLOAD_BASE, workBytes.length - OVERHEAD_SIZE);
			integrityHmac.update(workBytes, INITV_BASE, INITV_SIZE);
			return Ints.fromByteArray(integrityHmac.doFinal());
		} catch (InvalidKeyException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * Encrypts the winning price.
	 *
	 * @param priceValue
	 *            the price in micros (1/1.000.000th of the currency unit)
	 * @param initVector
	 *            up to 16 bytes of nonce data
	 * @return encrypted price
	 * @see #createInitVector(Date, long)
	 */
	public byte[] encryptPriceMicros(long priceValue, byte[] initVector) {
		byte[] plainData = initPlainData(PAYLOAD_SIZE, initVector);
		ByteBuffer.wrap(plainData).putLong(PAYLOAD_BASE, priceValue);
		return encrypt(plainData);
	}

	/**
	 * Decrypts the winning price.
	 *
	 * @param priceCipher
	 *            encrypted price
	 * @return the price value in micros (1/1.000.000th of the currency unit)
	 */
	public long decryptPriceMicros(byte[] priceCipher) throws SignatureException {
		checkArgument(priceCipher.length == (OVERHEAD_SIZE + PAYLOAD_SIZE), "Price is %s bytes, should be %s",
				priceCipher.length, (OVERHEAD_SIZE + PAYLOAD_SIZE));

		byte[] plainData = decrypt(priceCipher);
		return ByteBuffer.wrap(plainData).getLong(PAYLOAD_BASE);
	}

	/**
	 * Encrypts and encodes the winning price.
	 *
	 * @param priceMicros
	 *            the price in micros (1/1.000.000th of the currency unit)
	 * @param initVector
	 *            up to 16 bytes of nonce data, or {@code null} for default
	 *            generated data (see {@link #createInitVector(Date, long)}
	 * @return encrypted price, encoded as websafe-base64
	 */
	public String encodePriceMicros(long priceMicros, byte[] initVector) {
		return encode(encryptPriceMicros(priceMicros, initVector));
	}

	/**
	 * Encrypts and encodes the winning price.
	 *
	 * @param priceValue
	 *            the price
	 * @param initVector
	 *            up to 16 bytes of nonce data, or {@code null} for default
	 *            generated data (see {@link #createInitVector(Date, long)}
	 * @return encrypted price, encoded as websafe-base64
	 */
	public String encodePriceValue(double priceValue, byte[] initVector) {
		return encodePriceMicros((long) (priceValue * MICROS_PER_CURRENCY_UNIT), initVector);
	}

	/**
	 * Decodes and decrypts the winning price.
	 *
	 * @param priceCipher
	 *            encrypted price, encoded as websafe-base64
	 * @return the price value in micros (1/1.000.000th of the currency unit)
	 */
	public long decodePriceMicros(String priceCipher) throws SignatureException {
		return decryptPriceMicros(decode(checkNotNull(priceCipher)));
	}

	/**
	 * Decodes and decrypts the winning price.
	 *
	 * @param priceCipher
	 *            encrypted price, encoded as websafe-base64
	 * @return the price value
	 */
	public double decodePriceValue(String priceCipher) throws SignatureException {
		return decodePriceMicros(priceCipher) / ((double) MICROS_PER_CURRENCY_UNIT);
	}

	/**
	 * Packages plaintext payload for encryption; returns
	 * {@code initVector || payload || zeros:4}.
	 */
	private static byte[] initPlainData(int payloadSize, byte[] initVector) {
		byte[] plainData = new byte[OVERHEAD_SIZE + payloadSize];

		if (initVector == null) {
			ByteBuffer byteBuffer = ByteBuffer.wrap(plainData);
			byteBuffer.putLong(INITV_TIMESTAMP_OFFSET, System.nanoTime());
			byteBuffer.putLong(INITV_SERVERID_OFFSET, fastRandom.nextLong());
		} else {
			System.arraycopy(initVector, 0, plainData, INITV_BASE, min(INITV_SIZE, initVector.length));
		}

		return plainData;
	}

	private static String dump(String header, byte[] inData, byte[] workBytes) {
		ByteBuffer initvBuffer = ByteBuffer.wrap(workBytes, INITV_BASE, INITV_SIZE);
		Date timestamp = new Date(initvBuffer.getLong(INITV_BASE + INITV_TIMESTAMP_OFFSET));
		long serverId = initvBuffer.getLong(INITV_BASE + INITV_SERVERID_OFFSET);
		return new StringBuilder().append(header).append(": initVector={timestamp ")
				.append(DateFormat.getDateTimeInstance().format(timestamp)).append(", serverId ").append(serverId)
				.append("}, input =").append(BaseEncoding.base16().encode(inData)).append(", output =")
				.append(BaseEncoding.base16().encode(workBytes)).toString();
	}

	/**
	 * Decodes data, from string to binary form. The default implementation
	 * performs websafe-base64 decoding (RFC 3548).
	 */
	public static byte[] decode(String data) {
		return data == null ? null : BaseEncoding.base64Url().decode(data);
	}

	/**
	 * Encodes data, from binary form to string. The default implementation
	 * performs websafe-base64 encoding (RFC 3548).
	 */
	public static String encode(byte[] data) {
		return data == null ? null : BaseEncoding.base64Url().encode(data);
	}

	private static Mac createMac() {
		try {
			return Mac.getInstance(KEY_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static byte[] createInitVector(Date timestamp, long serverId) {
		byte[] initVector = new byte[INITV_SIZE];
		ByteBuffer byteBuffer = ByteBuffer.wrap(initVector);

		if (timestamp != null) {
			byteBuffer.putLong(INITV_TIMESTAMP_OFFSET, timestamp.getTime());
		}

		byteBuffer.putLong(INITV_SERVERID_OFFSET, serverId);
		return initVector;
	}

	/**
	 * Holds the keys used to configure price cryptography.
	 */
	public static class Keys {
		private final SecretKey encryptionKey;
		private final SecretKey integrityKey;

		public Keys(SecretKey encryptionKey, SecretKey integrityKey) throws InvalidKeyException {
			this.encryptionKey = encryptionKey;
			this.integrityKey = integrityKey;

			// Forces early failure if any of the keys are not good.
			// This allows us to spare callers from InvalidKeyException in
			// several methods.
			Mac hmac = createMac();
			hmac.init(encryptionKey);
			hmac.reset();
			hmac.init(integrityKey);
			hmac.reset();
		}

		public SecretKey getEncryptionKey() {
			return encryptionKey;
		}

		public SecretKey getIntegrityKey() {
			return integrityKey;
		}

		@Override
		public int hashCode() {
			return encryptionKey.hashCode() ^ integrityKey.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			} else if (!(obj instanceof Keys)) {
				return false;
			}
			Keys other = (Keys) obj;
			return encryptionKey.equals(other.encryptionKey) && integrityKey.equals(other.integrityKey);
		}

		@Override
		public String toString() {
			return MoreObjects.toStringHelper(this).omitNullValues()
					.add("encryptionKey", encryptionKey.getAlgorithm() + '/' + encryptionKey.getFormat())
					.add("integrityKey", integrityKey.getAlgorithm() + '/' + integrityKey.getFormat()).toString();
		}
	}

	public static class PriceInfo {
		private long price;
		private long currentTimeMillis;
		private long serverId;

		public PriceInfo(long price, long currentTimeMillis, long serverId) {
			this.price = price;
			this.currentTimeMillis = currentTimeMillis < 0 ? System.currentTimeMillis() : currentTimeMillis;
			this.serverId = serverId < 0 ? fastRandom.nextLong() : serverId;
		}

		public long getPrice() {
			return price;
		}

		public void setPrice(long price) {
			this.price = price;
		}

		public long getCurrentTimeMillis() {
			return currentTimeMillis;
		}

		public void setCurrentTimeMillis(long currentTimeMillis) {
			this.currentTimeMillis = currentTimeMillis;
		}

		public long getServerId() {
			return serverId;
		}

		public void setServerId(long serverId) {
			this.serverId = serverId;
		}
	}
}
