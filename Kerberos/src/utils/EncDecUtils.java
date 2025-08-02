package utils;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncDecUtils {

	// From 5th version (June 20024), Kerberos may use AES instead of DES
	public static SecretKeySpec generateKey(String password) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] key = digest.digest(password.getBytes(StandardCharsets.UTF_8));
		return new SecretKeySpec(key, "AES");
	}

	// In this file, encryption uses init vectors under-the-table to prevent CBC
	// vulnerabilities
	public static IvParameterSpec generateInitVector() throws NoSuchAlgorithmException {
		byte[] initVector = getTrueRandom(16);
		return new IvParameterSpec(initVector);
	}

	public static byte[] getTrueRandom(int len) throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstanceStrong();
		byte[] values = new byte[len];
		random.nextBytes(values);
		return values;
	}

	public static String hashSHA256(String input) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] messageDigest = md.digest(input.getBytes(StandardCharsets.UTF_8));
		StringBuilder sb = new StringBuilder();
		for (byte b : messageDigest) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	public static String encrypt(String data, SecretKeySpec key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		IvParameterSpec iv = generateInitVector();
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] encryptedBytes = cipher.doFinal(data.getBytes());

		byte[] encryptedBytesWithIv = new byte[iv.getIV().length + encryptedBytes.length];
		System.arraycopy(iv.getIV(), 0, encryptedBytesWithIv, 0, iv.getIV().length);
		System.arraycopy(encryptedBytes, 0, encryptedBytesWithIv, iv.getIV().length, encryptedBytes.length);
		return HexFormat.of().formatHex(encryptedBytesWithIv);
	}

	public static String decrypt(String ciphertext, SecretKeySpec key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] allBytes = HexFormat.of().parseHex(ciphertext);
		byte[] ivBytes = new byte[16];
		byte[] cipherBytes = new byte[allBytes.length - 16];

		System.arraycopy(allBytes, 0, ivBytes, 0, 16);
		System.arraycopy(allBytes, 16, cipherBytes, 0, cipherBytes.length);

		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] original = cipher.doFinal(cipherBytes);
		return new String(original);
	}

}
