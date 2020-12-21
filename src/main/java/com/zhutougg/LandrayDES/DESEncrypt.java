package com.zhutougg.LandrayDES;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DESEncrypt {
	private static final String ENCODING = "UTF-8";
	private static final String ALGORITHM_NAME = "DES";

	static {
		if (Security.getProvider("BC") == null) {
			Security.addProvider((Provider) new BouncyCastleProvider());
		}
	}

	private static String strDefaultKey = "kmssSecureKey";

	private Cipher encryptCipher = null;

	private Cipher decryptCipher = null;

	public DESEncrypt() throws Exception {
		this(strDefaultKey);
	}

	public DESEncrypt(String strKey) throws Exception {
		this(strKey, false);
	}

	@Deprecated
	public DESEncrypt(String strKey, boolean isRandom) throws Exception {
		Key key = null;
		if (!isRandom) {
			key = getKey(strKey);
		} else {
			key = getRandomKey(strKey);
		}
		this.encryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
		this.encryptCipher.init(1, key);

		this.decryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
		this.decryptCipher.init(2, key);
	}

	private Key getKey(String str) throws Exception {
		DESKeySpec dks = new DESKeySpec(str.getBytes("UTF-8"));
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES", "BC");
		return keyFactory.generateSecret(dks);
	}

	private Key getRandomKey(String str) throws Exception {
		KeyGenerator generator = KeyGenerator.getInstance("DES", "BC");
		generator.init(new SecureRandom(str.getBytes("UTF-8")));
		return generator.generateKey();
	}

	public byte[] encrypt(byte[] bytes) throws IllegalBlockSizeException, BadPaddingException {
		return this.encryptCipher.doFinal(bytes);
	}

	public byte[] decrypt(byte[] bytes) throws IllegalBlockSizeException, BadPaddingException {
		return this.decryptCipher.doFinal(bytes);
	}

	public InputStream decrypt(InputStream in) throws Exception {
		byte[] b = IOUtils.toByteArray(in);
		return new ByteArrayInputStream(decrypt(b));
	}

	public String encryptString(String str) throws Exception {
		return (new String(Base64.encodeBase64(encrypt(str.getBytes("UTF-8")), true), "UTF-8")).replaceAll("\n", "");
	}

	public String decryptString(String str) throws Exception {
		return new String(decrypt(Base64.decodeBase64(str.getBytes("UTF-8"))), "UTF-8");
	}

	public static void welcome() {
		System.out.println("請輸入參數");
		System.out.println("=============================");
		System.out.println("eg: Encrypt admin.do 123456");
		System.out.println("eg: Decrypt login.do edlR+Pow/ew=");
		System.out.println("Encrypt: 加密  Decrypt:解密");
		System.out.println("admin.do：後臺密碼   login.do  前臺密碼");
	}

	public static void main(String[] args) throws Exception {
		if (args.length == 0) {
			welcome();
			return;
		}
		String type = args[0];// 加密 or 解密
		String format = args[1];// admin.properties or 業務系統
		if ("Encrypt".equals(type)) {
			if ("admin.do".equals(format)) {
				DESEncrypt des = new DESEncrypt("kmssAdminKey");
				System.out.println(des.encryptString(args[2]));
			} else if ("login.do".equals(format)) {
				DESEncrypt des = new DESEncrypt("kmssPropertiesKey");
				System.out.println(des.encryptString(args[2]));
			} else {
				welcome();
			}
		} else if ("Decrypt".equals(type)) {
			if ("admin.do".equals(format)) {
				DESEncrypt des = new DESEncrypt("kmssAdminKey");
				System.out.println(des.decryptString(args[2]));
			} else if ("login.do".equals(format)) {
				DESEncrypt des = new DESEncrypt("kmssPropertiesKey");
				System.out.println(des.decryptString(args[2]));
			} else {
				welcome();
			}
		} else {
			welcome();
		}
	}
}
