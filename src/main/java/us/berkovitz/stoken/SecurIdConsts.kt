package us.berkovitz.stoken

enum class TokenGUID(val tag: String, val guidName: String, val guid: String){
	ANDROID("android", "Android", "a01c4380-fc01-4df0-b113-7fb98ec74694"),
	IPHONE("iphone", "iPhone", "556f1985-33dd-442c-9155-3a0e994f21b1"),
	BB("bb", "BlackBerry", "868c28f8-31bf-4911-9876-ebece5c3f2ab"),
	BB10("bb10", "BlackBerry 10", "b77a1d06-d505-4200-90d3-1bb397748704"),
	WINPHONE("winphone", "Windows Phone", "c483b592-63f0-4f19-b4cb-a6bce8e57159"),
	WIN("win", "Windows", "8f94b226-d362-4204-ac52-3b21fa333b6f"),
	MAC("mac", "Mac OSX", "d0955a53-569b-4ecc-9cf7-6c2a59d4e775")
}

class SecurIdConsts {
	companion object {
		const val AES_BLOCK_SIZE = 16
		const val AES_KEY_SIZE = 16
		const val SHA256_BLOCK_SIZE = 64
		const val SHA256_HASH_SIZE = 32
		const val MIN_PIN = 4
		const val MAX_PIN = 8
		const val MAX_PASS = 40
		const val MAGIC_LEN = 6
		const val VER_CHARS = 1
		const val SERIAL_CHARS = 12

		const val TOKEN_BITS_PER_CHAR = 3
		const val MIN_TOKEN_BITS = 189
		const val MAX_TOKEN_BITS = 255

		const val CHECKSUM_BITS = 15
		const val CHECKSUM_CHARS = (CHECKSUM_BITS / TOKEN_BITS_PER_CHAR)

		const val MAX_TOKEN_CHARS = (MAX_TOKEN_BITS / TOKEN_BITS_PER_CHAR)
		const val MIN_TOKEN_CHARS = ((MIN_TOKEN_BITS / TOKEN_BITS_PER_CHAR) +
				SERIAL_CHARS + VER_CHARS + CHECKSUM_CHARS)

		const val BINENC_BITS = 189
		const val BINENC_CHARS = (BINENC_BITS / TOKEN_BITS_PER_CHAR)
		const val BINENC_OFS = (VER_CHARS + SERIAL_CHARS)
		const val CHECKSUM_OFS = (BINENC_OFS + BINENC_CHARS)

		const val DEVID_CHARS = 40
		const val V3_DEVID_CHARS = 48
		const val V3_NONCE_BYTES = 16

		const val V3_BASE64_BYTES = 0x123
		val V3_BASE64_SIZE = base64InputLen(V3_BASE64_BYTES)
		const val V3_BASE64_MIN_CHARS	= (V3_BASE64_BYTES * 4 / 3)

		/* UNIX time_t for 2000/01/01 00:00:00 GMT */
		const val SECURID_EPOCH = 946684800
		const val SECURID_EPOCH_DAYS = (SECURID_EPOCH / (24*60*60))
		/* V3 tokens use 1970/01/01 as the epoch, but each day has 337500 ticks */
		const val SECURID_V3_DAY = 337500

		/* Avoid 32-bit time_t overflows (January 2038) */
		const val MAX_TIME_T = 0x7fffffff
		const val SECURID_MAX_SECS = (MAX_TIME_T - SECURID_EPOCH)
		const val SECURID_MAX_DATE = (SECURID_MAX_SECS / (24*60*60) - 1)

		val FL_128BIT = getBit(14)
		val FL_PASSPROT = getBit(13)
		val FL_SNPROT = getBit(12)
		val FL_APPSEEDS = getBit(11)
		val FL_FEAT4 = getBit(10)
		val FL_TIMESEEDS = getBit(9)
		const val FLD_DIGIT_SHIFT = 6
		const val FLD_DIGIT_MASK = 0x07 shl FLD_DIGIT_SHIFT
		val FL_FEAT6 = getBit(5)
		const val FLD_PINMODE_SHIFT = 3
		const val FLD_PINMODE_MASK = 0x03 shl FLD_PINMODE_SHIFT
		const val FLD_NUMSECONDS_SHIFT = 0
		const val FLD_NUMSECONDS_MASK = 0x03 shl FLD_NUMSECONDS_SHIFT

		val batchMacIv = byteArrayOf(
			0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae.toByte(), 0xd2.toByte(), 0xa6.toByte(),
			0xab.toByte(), 0xf7.toByte(), 0x15, 0x88.toByte(), 0x09, 0xcf.toByte(), 0x4f, 0x3c
		)

		val batchEncIv = byteArrayOf(0x32, 0x43, 0xf6.toByte(), 0xa8.toByte(),
			0x88.toByte(), 0x5a, 0x30, 0x8d.toByte(),
			0x31, 0x31, 0x98.toByte(), 0xa2.toByte(), 0xe0.toByte(), 0x37, 0x07, 0x34)

		val tokenMacIv = byteArrayOf(0x1b, 0xb6.toByte(), 0x7a, 0xe8.toByte(), 0x58,
			0x4c, 0xaa.toByte(), 0x73,
			0xb2.toByte(), 0x57, 0x42, 0xd7.toByte(), 0x07, 0x8b.toByte(), 0x83.toByte(), 0xb8.toByte())

		val tokenEncIv = byteArrayOf(0x16, 0xa0.toByte(), 0x9e.toByte(), 0x66,
			0x7f, 0x3b, 0xcc.toByte(), 0x90.toByte(),
			0x8b.toByte(), 0x2f, 0xb1.toByte(), 0x36, 0x6e, 0xa9.toByte(), 0x57, 0xd3.toByte())

		fun base64InputLen(x: Int): Int {
			return ((4 * ((x) + 2) / 3) + 1)
		}

		fun getBit(x: Int): Int {
			return 1 shl x
		}
	}
}
