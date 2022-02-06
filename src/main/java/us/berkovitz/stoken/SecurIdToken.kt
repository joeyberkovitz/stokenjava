package us.berkovitz.stoken

import java.io.ByteArrayOutputStream
import java.nio.charset.Charset
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or
import kotlin.experimental.xor

class SecurIdToken() {
	var version: Int = 0
	var serial: String = ""
	var flags: Int = 0
	var expDate: Int = 0
	var isSmartphone = false

	var hasEncSeed = false
	var encSeed = ByteArray(16)

	var decSeedHash: Int = 0
	var deviceIdHash: Int = 0

	var hasDecSeed = false
	var decSeed = ByteArray(16)

	var pinMode = 0
	var pin = ""

	var interactive = false

	constructor(copyToken: SecurIdToken) : this() {
		this.version = copyToken.version
		this.serial = copyToken.serial
		this.flags = copyToken.flags
		this.expDate = copyToken.expDate
		this.isSmartphone = copyToken.isSmartphone
		this.hasEncSeed = copyToken.hasEncSeed
		this.encSeed = copyToken.encSeed
		this.decSeedHash = copyToken.decSeedHash
		this.deviceIdHash = copyToken.deviceIdHash
		this.hasDecSeed = copyToken.hasDecSeed
		this.decSeed = copyToken.decSeed
		this.pinMode = copyToken.pinMode
		this.pin = copyToken.pin
		this.interactive = copyToken.interactive
	}

	companion object {
		fun importString(tokenString: String, interactive: Boolean): SecurIdToken {
			val securIdToken = SecurIdToken()
			securIdToken.interactive = interactive
			when {
				tokenString.contains("ctfData=3D", true) -> {
					return parseCtfStr(tokenString, securIdToken)
				}
				tokenString.contains("ctfData=", true) -> {
					return parseCtfStr(tokenString, securIdToken)
				}
				tokenString.contains("<?xml ", true) -> {
					return parseXmlStr(tokenString, securIdToken)
				}
				tokenString.isNotEmpty() && tokenString[0].isDigit() -> {
					return parseCtfStr(tokenString, securIdToken)
				}
				else -> {
					throw Exception("unknown token type")
				}
			}
		}

		private fun parseCtfStr(ctfStr: String, securIdToken: SecurIdToken): SecurIdToken {
			val tokenStr = if(ctfStr.contains("ctfData=3D", true))
				ctfStr.substring(ctfStr.indexOf("ctfData=3D", 0, true) + 10)
			else if(ctfStr.contains("ctfData=", true))
				ctfStr.substring(ctfStr.indexOf("ctfData=", 0, true) + 8)
			else ctfStr
			var parseToken = tokenStr
			if(tokenStr[0] == '1' || tokenStr[0] == '2'){
				val tokenBuilder = StringBuilder()
				for(char in tokenStr){
					if(char.isDigit())
						tokenBuilder.append(char)
					else if (char != '-')
						break
				}
				parseToken = tokenBuilder.toString()
			} else if(tokenStr[0] != 'A') {
				throw Exception("unknown token type")
			}

			securIdToken.decodeToken(parseToken)

			if(ctfStr.startsWith("com.rsa.securid.iphone://ctf")
				|| ctfStr.startsWith("com.rsa.securid://ctf")
				|| ctfStr.startsWith("http://127.0.0.1/securid/ctf"))
				securIdToken.isSmartphone = true
			return securIdToken
		}

		private fun parseXmlStr(ctfStr: String, securIdToken: SecurIdToken): SecurIdToken {
			return SecurIdToken()
		}

		private fun numInputToBits(strIn: String, numBits: Int): ByteArray {
			var bitPos = 13
			val outArr = ByteArray((numBits + 7)/8) { 0 }

			var bitRemain = numBits
			var strPos = 0
			var outPos = 0
			while (bitRemain > 0){
				var decoded = (strIn[strPos].code and 0x07)
				decoded = decoded shl bitPos

				outArr[outPos] = (outArr[outPos].toInt() or (decoded ushr 8)).toByte()
				outArr[outPos + 1] = (outArr[outPos + 1].toInt() or (decoded and 0xFF)).toByte()

				bitPos -= SecurIdConsts.TOKEN_BITS_PER_CHAR
				if (bitPos < 0){
					bitPos += 8
					outPos++
				}

				bitRemain -= SecurIdConsts.TOKEN_BITS_PER_CHAR
				strPos++
			}
			return outArr
		}

		private fun bitsToNumOutput(bytesIn: ByteArray, numBits_: Int): String {
			val stringOut = StringBuilder()
			var bitPos = 13
			var numBits = numBits_
			var inPos = 0

			while(numBits > 0){
				val binVal = (bytesIn[inPos].toUByte().toUInt() shl 8) or bytesIn[inPos + 1].toUByte().toUInt()
				val outChar = ((binVal shr bitPos) and 0x07u) + '0'.code.toUInt()
				stringOut.append(outChar.toInt().toChar())

				bitPos -= SecurIdConsts.TOKEN_BITS_PER_CHAR
				if(bitPos < 0){
					bitPos += 8
					inPos++
				}
				numBits -= SecurIdConsts.TOKEN_BITS_PER_CHAR
			}

			return stringOut.toString()
		}

		private fun getBits(inBytes: ByteArray, start: Int, numBits_: Int): Int {
			var out = 0
			var inPos = start / 8
			var startPos = start % 8
			var numBits = numBits_

			while(numBits > 0){
				out = out shl 1
				if(((inBytes[inPos].toInt() shl startPos) and 0x80) != 0){
					out = out or 0x01
				}
				startPos++
				if(startPos == 8){
					startPos = 0
					inPos++
				}
				numBits--
			}

			return out
		}

		private fun setBits(outArr: ByteArray, start_: Int, numBits_: Int, setVal_: Int){
			var outPos = start_ / 8
			var start = start_ % 8
			var setVal = setVal_ shl (32 - numBits_)
			var numBits = numBits_

			while (numBits > 0){
				if(setVal and SecurIdConsts.getBit(31) != 0)
					outArr[outPos] = outArr[outPos] or SecurIdConsts.getBit(7 - start).toByte()
				else
					outArr[outPos] = outArr[outPos] and SecurIdConsts.getBit(7 - start).toByte().inv()

				setVal = setVal shl 1
				start++
				if(start == 8){
					start = 0
					outPos++
				}
				numBits--
			}
		}

		private fun securidShortmac(inBytes: ByteArray): Int {
			val hash = securidMac(inBytes)
			return (hash[0].toUByte().toInt() shl 7) or (hash[1].toUByte().toInt() shr 1)
		}

		private fun encryptThenXor(key: ByteArray, work: ByteArray) {
			val enc = Crypto.stcAes128EcbEncrypt(key, work)
			for(i in 0 until SecurIdConsts.AES_BLOCK_SIZE){
				work[i] = work[i] xor enc[i]
			}
		}

		private fun securidMac(inBytes: ByteArray): ByteArray {
			var i = 0
			var odd = false
			val incr = SecurIdConsts.AES_KEY_SIZE
			val work = ByteArray(incr){(0xFF).toByte()}
			val pad = ByteArray(incr)
			val zero = ByteArray(incr)
			val lastBlk = ByteArray(incr)

			// Padding
			var padPos = incr - 1
			i = inBytes.size * 8
			while (i > 0){
				pad[padPos] = i.toByte()
				padPos--
				i = i ushr 8
			}

			/* handle the bulk of the input data here */
			var inRemain = inBytes.size
			var inStart = 0
			while (inRemain > incr) {
				encryptThenXor(inBytes.copyOfRange(inStart, inStart + incr), work)
				inRemain -= incr
				inStart += incr
				odd = !odd
			}

			/* final 0-16 bytes of input data */
			inBytes.copyInto(lastBlk, 0, inStart, inStart + inRemain)
			encryptThenXor(lastBlk, work)

			/* hash an extra block of zeroes, for certain input lengths */
			if (odd)
				encryptThenXor(zero, work);

			/* always hash the padding */
			encryptThenXor(pad, work);

			/* run hash over current hash value, then return */
			val out = work.copyOfRange(0, incr)
			encryptThenXor(work, out);
			return out
		}

		fun pinFormatOk(pin: String): Boolean {
			val rc = pin.length
			if(rc < SecurIdConsts.MIN_PIN || rc > SecurIdConsts.MAX_PIN)
				return false
			for(char in pin)
				if(!char.isDigit())
					return false
			return true
		}

		private fun bcdWrite(outArr: ByteArray, startPos: Int, writeVal_: Int, numBytes_: Int){
			var outPos = startPos + numBytes_ - 1
			var writeVal = writeVal_
			var numBytes = numBytes_
			while(numBytes > 0){
				outArr[outPos] = (writeVal % 10).toByte()
				writeVal /= 10
				outArr[outPos] = outArr[outPos] or ((writeVal % 10) shl 4).toByte()
				writeVal /= 10

				outPos--
				numBytes--
			}
		}
	}

	fun decodeToken(tokenStr: String){
		/*
		 * V1/V2 tokens start with the ASCII version digit
		 * V3 tokens always start with a base64-encoded 0x03 byte, which
		 *   is guaranteed to encode to 'A'
		 */
		if(tokenStr[0] == '1' || tokenStr[0] == '2')
			return decodeV2Token(tokenStr)
		else if(tokenStr.length >= (0x123 * 4 / 3) && tokenStr[0] == 'A')
			return decodeV3Token(tokenStr)

		throw Exception("unknown token type")
	}

	private fun decodeV2Token(tokenStr: String){
		val len = tokenStr.length

		if (len < SecurIdConsts.MIN_TOKEN_CHARS || len > SecurIdConsts.MAX_TOKEN_CHARS)
			throw Exception("invalid token length")

		/* the last 5 digits provide a checksum for the rest of the string */
		val checksum = numInputToBits(tokenStr.substring(len - SecurIdConsts.CHECKSUM_CHARS), 15)
		val tokenMac = getBits(checksum, 0, 15)
		val computedMac = securidShortmac(tokenStr.substring(0, len - SecurIdConsts.CHECKSUM_CHARS).toByteArray())

		if(tokenMac != computedMac)
			throw Exception("checksum failed")

		this.version = tokenStr[0] - '0'
		this.serial = tokenStr.substring(SecurIdConsts.VER_CHARS, SecurIdConsts.VER_CHARS + SecurIdConsts.SERIAL_CHARS)

		val decoded = numInputToBits(tokenStr.substring(SecurIdConsts.BINENC_OFS), SecurIdConsts.BINENC_BITS)
		encSeed = decoded.copyOfRange(0, SecurIdConsts.AES_KEY_SIZE)
		this.hasEncSeed = true

		this.flags = getBits(decoded, 128, 16)
		this.expDate = getBits(decoded, 144, 14)
		this.decSeedHash = getBits(decoded, 159, 15)
		this.deviceIdHash = getBits(decoded, 174, 15)
	}

	private fun decodeV3Token(tokenStr: String){
		throw Exception("unimplemented")
	}

	fun pinRequired(): Boolean {
		return ((this.flags and SecurIdConsts.FLD_PINMODE_MASK) ushr SecurIdConsts.FLD_PINMODE_SHIFT) >= 2
	}

	fun passRequired(): Boolean {
		return (this.flags and SecurIdConsts.FL_PASSPROT) == SecurIdConsts.FL_PASSPROT
	}

	fun devIdRequired(): Boolean {
		return (flags and SecurIdConsts.FL_SNPROT) == SecurIdConsts.FL_SNPROT
	}

	fun checkDevId(devId: String): Boolean {
		try {
			decryptSeed(".", devId)
		} catch (exc: InvalidDeviceIdException) {
			return false
		} catch (exc: Exception){
			return true
		}

		return true
	}

	fun tokenInterval(): Int {
		if (((flags and SecurIdConsts.FLD_NUMSECONDS_MASK) ushr SecurIdConsts.FLD_NUMSECONDS_SHIFT) == 0)
			return 30
		else
			return 60
	}

	fun unixExpDate(): Int {
		/*
		 * v3 tokens encrypt the expiration date, so if the user has not
		 * been prompted for a password yet, we'll need to bypass the
		 * expiration checks.
		 */
		if (version == 3 && expDate == 0)
			return SecurIdConsts.MAX_TIME_T
		if (expDate > SecurIdConsts.SECURID_MAX_DATE)
			return SecurIdConsts.MAX_TIME_T

		return SecurIdConsts.SECURID_EPOCH + (expDate + 1) * 60 * 60 * 24
	}

	private fun keyFromTime(bcdTime: ByteArray, bcdTimeBytes: Int): ByteArray {
		val key = ByteArray(SecurIdConsts.AES_KEY_SIZE)

		for(i in 0 until 8)
			key[i] = (0xAA).toByte()
		bcdTime.copyInto(key, 0, 0, bcdTimeBytes)
		for(i in 12 until 16)
			key[i] = (0xBB).toByte()

		/* write BCD-encoded partial serial number */
		var keyPos = 8
		for (i in 4 until 12 step 2)
			key[keyPos++] = (((serial[i] - '0') shl 4) or (serial[i + 1] - '0')).toByte();
		return key
	}

	fun computeTokenCode(timeInSecs: Long, pin: String): String {
		if(pinRequired()){
			if(pin.isNotEmpty()){
				if(!pinFormatOk(pin))
					throw Exception("invalid pin")
				this.pin = pin
			} else if (this.pin.isEmpty())
				throw Exception("pin required")
		}

		val pinLen = this.pin.length
		val is30 = tokenInterval() == 30
		val calendarTime = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendarTime.timeInMillis = timeInSecs * 1000

		val bcdTime = ByteArray(8)
		bcdWrite(bcdTime, 0, calendarTime.get(Calendar.YEAR), 2)
		bcdWrite(bcdTime, 2, calendarTime.get(Calendar.MONTH) + 1, 1)
		bcdWrite(bcdTime, 3, calendarTime.get(Calendar.DAY_OF_MONTH), 1)
		bcdWrite(bcdTime, 4, calendarTime.get(Calendar.HOUR_OF_DAY), 1)
		val minMask =  (if (is30) 0x01 else 0x03).toByte().inv()
		bcdWrite(bcdTime, 5, calendarTime.get(Calendar.MINUTE) and minMask.toUInt().toInt(), 1)
		bcdTime[6] = 0
		bcdTime[7] = 0

		var key0 = keyFromTime(bcdTime, 2)
		key0 = Crypto.stcAes128EcbEncrypt(decSeed, key0)
		var key1 = keyFromTime(bcdTime, 3)
		key1 = Crypto.stcAes128EcbEncrypt(key0, key1)
		key0 = keyFromTime(bcdTime, 4)
		key0 = Crypto.stcAes128EcbEncrypt(key1, key0)
		key1 = keyFromTime(bcdTime, 5)
		key1 = Crypto.stcAes128EcbEncrypt(key0, key1)
		key0 = keyFromTime(bcdTime, 8)
		key0 = Crypto.stcAes128EcbEncrypt(key1, key0)

		/* key0 now contains 4 consecutive token codes */
		var i = if(is30)
			((calendarTime.get(Calendar.MINUTE) and 0x01) shl 3) or
					((if(calendarTime.get(Calendar.SECOND) >= 30) 1 else 0) shl 2)
		else (calendarTime.get(Calendar.MINUTE) and 0x03) shl 2
		var tokenCode = ((key0[i + 0].toUByte().toInt() shl 24) or (key0[i + 1].toUByte().toInt() shl 16) or
				(key0[i + 2].toUByte().toInt() shl 8) or (key0[i + 3].toUByte().toInt() shl 0)).toUInt()

		/* populate code_out backwards, adding PIN digits if available */
		var j = ((flags and SecurIdConsts.FLD_DIGIT_MASK) ushr SecurIdConsts.FLD_DIGIT_SHIFT)
		val codeOut = ByteArray(j + 1)
		i = 0
		while (j >= 0){
			var c = tokenCode % 10u
			tokenCode /= 10u

			if(i < pinLen)
				c += (this.pin[pinLen - i - 1] - '0').toUInt()
			codeOut[j] = ((c % 10u) + '0'.code.toUInt()).toByte()

			j--
			i++
		}
		return codeOut.toString(Charset.defaultCharset())
	}

	fun decryptSeed(pass_: String, devId_: String){
		var pass = pass_
		var devId = devId_
		if(passRequired()){
			if(pass.isEmpty())
				throw Exception("password required")
			if(pass.length > SecurIdConsts.MAX_PASS)
				throw Exception("password overflow")
		} else pass = ""

		if(flags and SecurIdConsts.FL_SNPROT != 0){
			if(devId.isEmpty())
				throw Exception("devId required")
		} else devId = ""

		//TODO: sdtid
		//TODO: v3
		return v2DecryptSeed(pass, devId)
	}

	private fun generateKeyHash(pass: String, devId: String): Pair<Int, ByteArray> {
		var devIdHash: Int = 0
		var pos = 0
		val key = ByteArray(SecurIdConsts.MAX_PASS + SecurIdConsts.DEVID_CHARS + SecurIdConsts.MAGIC_LEN + 1)
		val devIdLen = if(isSmartphone) 40 else 32
		val magic = byteArrayOf((0xd8).toByte(), (0xf5).toByte(), 0x32, 0x53, (0x82).toByte(), (0x89).toByte(), 0x00)

		if(pass.isNotEmpty()){
			pos = pass.length
			if(pos > SecurIdConsts.MAX_PASS)
				throw Exception("password overflow")
			pass.toByteArray().copyInto(key, 0, 0, pass.length)
		}
		val devIdStart = pos
		if(devId.isNotEmpty()){
			var len = 0
			/*
			 * For iPhone/Android ctf strings, the device ID takes up
			 * 40 bytes and consists of hex digits + zero padding.
			 *
			 * For other ctf strings (e.g. --blocks), the device ID takes
			 * up 32 bytes and consists of decimal digits + zero padding.
			 *
			 * If this seed isn't locked to a device, we'll just hash
			 * 40 (or 32) zero bytes, below.
			 */
			for(devIdPos in devId.indices){
				if(++len > devIdLen)
					break
				if((version == 1 && devId[devIdPos].isDigit()) ||
					(version >= 2 && !devId[devIdPos].isLetterOrDigit()))
					continue
				key[pos++] = devId[devIdPos].uppercaseChar().code.toByte()
			}
		}

		devIdHash = securidShortmac(key.copyOfRange(devIdStart, devIdStart + devIdLen))

		magic.copyInto(key, pos, 0, SecurIdConsts.MAGIC_LEN)
		val keyHash = securidMac(key.copyOfRange(0, pos + SecurIdConsts.MAGIC_LEN))

		return Pair(devIdHash, keyHash)
	}

	private fun v2DecryptSeed(pass: String, devId: String){
		val res = generateKeyHash(pass, devId)

		if(flags and SecurIdConsts.FL_SNPROT != 0 && deviceIdHash != res.first)
			throw InvalidDeviceIdException("invalid device id")

		decSeed = Crypto.stcAes128EcbDecrypt(res.second, encSeed)
		var computedMac = securidShortmac(decSeed)
		if(computedMac != decSeedHash)
			throw Exception("decrypt failed")
		hasDecSeed = true
	}

	fun encodeToken(pass: String, devId: String, exportVersion: Int): String {
		val newToken = SecurIdToken(this)

		if(pass.isEmpty())
			newToken.flags = newToken.flags and SecurIdConsts.FL_PASSPROT.inv()
		else
			newToken.flags = newToken.flags or SecurIdConsts.FL_PASSPROT

		if(devId.isEmpty())
			newToken.flags = newToken.flags and SecurIdConsts.FL_SNPROT.inv()
		else
			newToken.flags = newToken.flags or SecurIdConsts.FL_SNPROT

		if(exportVersion == 3)
			return newToken.v3EncodeToken(pass, devId)
		return newToken.v2EncodeToken(pass, devId)
	}

	private fun v3EncodeToken(pass: String, devId: String): String {
		throw Exception("unimplemented")
	}

	private fun v2EncodeToken(pass: String, devId: String): String {
		val keyHash = generateKeyHash(pass, devId)
		val outBytes = ByteArray(SecurIdConsts.MAX_TOKEN_BITS / 8 + 2)
		val stringOut = StringBuilder("2")

		this.encSeed = Crypto.stcAes128EcbEncrypt(keyHash.second, this.decSeed)
		this.encSeed.copyInto(outBytes, 0, 0, SecurIdConsts.AES_KEY_SIZE)

		setBits(outBytes, 128, 16, flags)
		setBits(outBytes, 144, 14, expDate)
		setBits(outBytes, 159, 15, securidShortmac(decSeed))
		setBits(outBytes, 174, 15, keyHash.first)
		stringOut.append(serial)

		stringOut.append(bitsToNumOutput(outBytes, SecurIdConsts.BINENC_BITS))
		setBits(outBytes, 0, 15, securidShortmac(stringOut.toString().toByteArray().copyOfRange(0, SecurIdConsts.CHECKSUM_OFS)))
		stringOut.append(bitsToNumOutput(outBytes, SecurIdConsts.CHECKSUM_BITS))
		return stringOut.toString()
	}

}
