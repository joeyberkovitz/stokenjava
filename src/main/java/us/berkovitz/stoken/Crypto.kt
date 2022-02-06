package us.berkovitz.stoken

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Crypto {
	companion object {
		fun stcAes128EcbEncrypt(key: ByteArray, inBytes: ByteArray): ByteArray {
			val cipher = Cipher.getInstance("AES/ECB/NoPadding")
			val secKey = SecretKeySpec(key, "AES")
			cipher.init(Cipher.ENCRYPT_MODE, secKey)
			return cipher.doFinal(inBytes)
		}

		fun stcAes128EcbDecrypt(key: ByteArray, inBytes: ByteArray): ByteArray {
			val cipher = Cipher.getInstance("AES/ECB/NoPadding")
			val secKey = SecretKeySpec(key, "AES")
			cipher.init(Cipher.DECRYPT_MODE, secKey)
			return cipher.doFinal(inBytes)
		}
	}
}
