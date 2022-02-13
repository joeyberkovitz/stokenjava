package us.berkovitz.stoken

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.xml.sax.InputSource
import java.io.StringReader
import java.lang.Integer.min
import java.text.SimpleDateFormat
import java.util.*
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.experimental.xor

class Sdtid() {
	var importDoc: Document? = null
	var token: SecurIdToken = SecurIdToken()
	var headerElement: Element? = null
	var tokenDoc: Element? = null
	var sn = ""

	var batchMacKey = ByteArray(0)
	var tokenEncKey = ByteArray(0)
	var tokenMacKey = ByteArray(0)

	companion object {
		private fun lookupNode(element: Element, headerElement: Element?, searchTag: String): Node? {
			val findNode = element.getElementsByTagName(searchTag)
			if(findNode.length > 0)
				return findNode.item(0)

			if(headerElement == null) return null

			val findNodeDef = headerElement.getElementsByTagName("Def$searchTag")
			if(findNodeDef.length > 0)
				return findNodeDef.item(0)

			val findNodeHdr = headerElement.getElementsByTagName(searchTag)
			if(findNodeHdr.length > 0)
				return findNodeHdr.item(0)
			return null
		}

		fun lookupInt(element: Element, headerElement: Element?, searchTag: String, defaultVal: Int): Int {
			val searchNode = lookupNode(element, headerElement, searchTag) ?: return defaultVal
			val resStr = searchNode.textContent
			return try {
				resStr.toInt()
			} catch (exc: Exception){
				defaultVal
			}
		}

		fun lookupString(element: Element, headerElement: Element?, searchTag: String, defaultVal: String?): String? {
			val searchNode = lookupNode(element, headerElement, searchTag) ?: return defaultVal
			return searchNode.textContent
		}
	}

	constructor(tokenText: String) : this() {
		token.sdtidDoc = this
		val dbf = DocumentBuilderFactory.newInstance()
		//dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)

		val db = dbf.newDocumentBuilder()
		importDoc = db.parse(InputSource(StringReader(tokenText)))
		importDoc?.documentElement?.normalize()
		parseXml(importDoc!!)
	}

	@Throws(Exception::class)
	private fun parseXml(doc: Document){
		val batchSearch = doc.getElementsByTagName("TKNBatch")
		if(batchSearch.length == 0)
			throw Exception("missing TKNBatch")
		val batch = batchSearch.item(0).childNodes

		val headerList = doc.getElementsByTagName("TKNHeader")
		if(headerList.length == 1 && headerList.item(0) is Element)
			headerElement = headerList.item(0) as Element

		val trailer = doc.getElementsByTagName("TKNTrailer")

		var tokenCount = 0
		for(i in 0 until batch.length){
			val currNode = batch.item(i)
			if(currNode.nodeName != "TKN")
				continue
			if(tokenCount > 0)
				throw Exception("too many tokens")
			if(currNode is Element)
				tokenDoc = currNode
			else
				throw Exception("TKN is not an element")
			tokenCount++
		}

		if(tokenDoc == null)
			throw Exception("no tokens found")

		val serialNode = tokenDoc!!.getElementsByTagName("SN")
		if(serialNode.length != 1)
			throw Exception("SN not found")

		token.serial = serialNode.item(0).textContent
		if(token.serial.length > SecurIdConsts.SERIAL_CHARS)
			throw Exception("SN too long")
		else if(token.serial.length < SecurIdConsts.SERIAL_CHARS)
			token.serial.padStart(SecurIdConsts.SERIAL_CHARS, '0')

		if(lookupInt(tokenDoc!!, headerElement, "TimeDerivedSeeds", 0) != 0)
			token.flags = token.flags or SecurIdConsts.FL_TIMESEEDS

		if(lookupInt(tokenDoc!!, headerElement, "AppDerivedSeeds", 0) != 0)
			token.flags = token.flags or SecurIdConsts.FL_APPSEEDS

		if(lookupInt(tokenDoc!!, headerElement, "Mode", 0) != 0)
			token.flags = token.flags or SecurIdConsts.FL_FEAT4

		if(lookupInt(tokenDoc!!, headerElement, "Alg", 0) != 0)
			token.flags = token.flags or SecurIdConsts.FL_128BIT


		var pinFlag = 0
		if(lookupInt(tokenDoc!!, headerElement, "AddPIN", 0) != 0)
			pinFlag = pinFlag or 0b10
		if(lookupInt(tokenDoc!!, headerElement, "LocalPIN", 0) != 0)
			pinFlag = pinFlag or 0b01
		token.flags = token.flags or pinFlag

		val digits = lookupInt(tokenDoc!!, headerElement, "Digits", 6) - 1
		token.flags = token.flags or ((digits shl SecurIdConsts.FLD_DIGIT_SHIFT) and SecurIdConsts.FLD_DIGIT_MASK)

		if(lookupInt(tokenDoc!!, headerElement, "Interval", 60) == 60)
			token.flags = token.flags or (1 shl SecurIdConsts.FLD_NUMSECONDS_SHIFT)

		val expDateStr = lookupString(tokenDoc!!, headerElement, "Death", null)
		if(expDateStr != null && expDateStr.isNotBlank()){
			val dateFormat = SimpleDateFormat("YYYY/MM/dd")
			dateFormat.timeZone = TimeZone.getTimeZone("GMT")
			try {
				val date = dateFormat.parse(expDateStr)
				token.expDate = ((date.time/1000 - SecurIdConsts.SECURID_EPOCH) / (24*60*60)).toInt()
			} catch (exc: Exception){
				throw Exception("invalid expiration date")
			}
		}

		try {
			decrypt("")
		} catch (exc: PasswordRequiredException){
			token.flags = token.flags or SecurIdConsts.FL_PASSPROT
		}
	}

	fun passRequired(): Boolean = token.passRequired()

	@Throws(Exception::class, PasswordRequiredException::class)
	fun decrypt(pass: String) {
		genKeys(pass)

		val seed = lookupString(tokenDoc!!, headerElement, "Seed", "")!!
		if(seed.isBlank())
			throw Exception("seed missing")
		token.encSeed = try {
			Base64.getDecoder().decode(seed.substring(1))
		} catch (exc: Exception) {
			throw Exception("invalid seed base64")
		}
		token.hasEncSeed = true

		val goodMac0B64 = lookupString(tokenDoc!!, headerElement, "HeaderMAC", "")!!
		if(goodMac0B64.isBlank())
			throw Exception("HeaderMAC missing")
		val goodMac0 = try {
			Base64.getDecoder().decode(goodMac0B64)
		} catch (exc: Exception) { throw Exception("invalid HeaderMAC") }

		val goodMac1B64 = lookupString(tokenDoc!!, headerElement, "TokenMAC", "")!!
		if(goodMac1B64.isBlank())
			throw Exception("TokenMAC missing")
		val goodMac1 = try {
			Base64.getDecoder().decode(goodMac1B64)
		} catch (exc: Exception) { throw Exception("invalid TokenMAC") }

		val mac0 = hashSection(headerElement as Node, batchMacKey, SecurIdConsts.batchMacIv)
		val mac1 = hashSection(tokenDoc as Node, tokenMacKey, SecurIdConsts.tokenMacIv)

		val mac0Pass = mac0.contentEquals(goodMac0)
		val mac1Pass = mac1.contentEquals(goodMac1)

		if(!mac0Pass && !mac1Pass){
			if(pass.isBlank()) throw PasswordRequiredException("password missing")
			else throw Exception("decryption failed")
		}

		if(!mac0Pass)
			throw Exception("header MAC check failed")
		else if(!mac1Pass)
			throw Exception("token MAC check failed")

		token.decSeed = decryptSeed(token.encSeed, sn, tokenEncKey)
		token.hasDecSeed = true
	}

	private fun genKeys(pass: String){
		sn = lookupString(tokenDoc!!, headerElement, "SN", "")!!
		val origin = lookupString(tokenDoc!!, headerElement, "Origin", "")!!
		val dest = lookupString(tokenDoc!!, headerElement, "Dest", "")!!
		val name = lookupString(tokenDoc!!, headerElement, "Name", "")!!
		val secretB64 = lookupString(tokenDoc!!, headerElement, "Secret", "")!!
		if(sn.isBlank() || origin.isBlank() || dest.isBlank() || name.isBlank() || secretB64.isBlank())
			throw Exception("missing required string")

		val secret = try {
			Base64.getDecoder().decode(secretB64)
		} catch (exc: Exception) {
			throw Exception("invalid b64 secret")
		}

		val passStr = pass.ifBlank { origin }
		val key0 = hashPassword(passStr, dest, name)
		val key1 = decryptSecret(secret, name, key0)

		batchMacKey = calcKey("BatchMAC", name, key1, SecurIdConsts.batchMacIv)
		tokenMacKey = calcKey("TokenMAC", sn, key1, SecurIdConsts.tokenMacIv)
		tokenEncKey = calcKey("TokenEncrypt", sn, key1, SecurIdConsts.tokenEncIv)
	}

	private fun xorBlock(outArr: ByteArray, inArr: ByteArray) {
		//TODO: AES_BLOCK_SIZE or length?
		for(i in 0 until SecurIdConsts.AES_BLOCK_SIZE){
			outArr[i] = outArr[i] xor inArr[i]
		}
	}

	private fun cbcHash(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
		var result: ByteArray = iv.copyOf()
		var len = data.size
		var pos = 0
		while (len > 0){
			var currData = data.copyOfRange(pos, min(pos + SecurIdConsts.AES_BLOCK_SIZE, data.size))
			if(currData.size < SecurIdConsts.AES_BLOCK_SIZE)
				currData += ByteArray(SecurIdConsts.AES_BLOCK_SIZE - currData.size)

			if(len >= SecurIdConsts.AES_BLOCK_SIZE)
				xorBlock(result, currData)
			else {
				var tmp = currData.copyOf()
				if(tmp.size < SecurIdConsts.AES_BLOCK_SIZE)
					tmp += ByteArray(SecurIdConsts.AES_BLOCK_SIZE - tmp.size)
				xorBlock(result, tmp)
			}

			result = Crypto.stcAes128EcbEncrypt(key, result)

			len -= SecurIdConsts.AES_BLOCK_SIZE
			pos += SecurIdConsts.AES_BLOCK_SIZE
		}
		return result
	}


	private fun hashPassword(pass: String, salt0: String, salt1: String): ByteArray {
		val key = ByteArray(SecurIdConsts.AES_KEY_SIZE)
		val result = ByteArray(SecurIdConsts.AES_BLOCK_SIZE)
		/* FIXME: this should probably use a hash if salt1 is >16 chars */
		salt1.toByteArray().copyInto(key, 0, 0, min(key.size, salt1.length))

		var data = ByteArray(0)
		data += pass.padEnd(0x20, Char(0)).substring(0, 0x20).toByteArray()
		data += salt0.padEnd(0x20, Char(0)).substring(0, 0x20).toByteArray()
		data += ByteArray(0x10)

		var tmp: ByteArray
		for(i in 0 until 1000){
			data[0x4F] = i.toByte()
			data[0x4E] = (i ushr 8).toByte()
			tmp = cbcHash(key, ByteArray(SecurIdConsts.AES_BLOCK_SIZE), data)
			xorBlock(result, tmp)
		}
		return result
	}

	private fun decryptSecret(encBin: ByteArray, str0: String, key: ByteArray): ByteArray {
		var result = ByteArray(0)
		result += ("Secret\u0000\u0000").toByteArray()
		result += str0.padEnd(8, Char(0)).substring(0, 8).toByteArray()

		result = Crypto.stcAes128EcbEncrypt(key, result)
		xorBlock(result, encBin)
		return result
	}

	private fun decryptSeed(encBin: ByteArray, str0: String, key: ByteArray): ByteArray {
		var result = ByteArray(0)
		result += str0.padEnd(8, Char(0)).substring(0, 8).toByteArray()
		result += ("Seed\u0000\u0000\u0000\u0000").toByteArray()

		result = Crypto.stcAes128EcbEncrypt(key, result)
		xorBlock(result, encBin)
		return result
	}

	private fun calcKey(str0: String, str1: String, key: ByteArray, iv: ByteArray): ByteArray {
		var buf = ByteArray(0)
		buf += str0.padEnd(0x20, Char(0)).substring(0, 0x20).toByteArray()
		buf += str1.padEnd(0x20, Char(0)).substring(0, 0x20).toByteArray()
		return cbcHash(key, iv, buf)
	}

	inner class HashState {
		var root: Node? = null
		var data = ByteArray(65536)
		var pos = 0
		var padding = 0
		var signing = false
	}

	private fun hashSection(node: Node, key: ByteArray, iv: ByteArray): ByteArray {
		val hashState = HashState()
		hashSectionInternal(hashState, node, false)
		return cbcHash(key, iv, hashState.data.copyOfRange(0, hashState.pos))
	}

	private fun hashSectionInternal(hashState: HashState, node: Node, signing: Boolean){
		hashState.root = node
		hashState.signing = signing
		recursiveHash(hashState, node.nodeName, node)
	}

	private fun recursiveHash(hashState: HashState, pfx: String, parent: Node): Int {
		var children = 0

		for(i in 0 until parent.childNodes.length){
			val node = parent.childNodes.item(i)!!
			val name = node.nodeName
			val remain = 65536 - hashState.pos
			if(node.nodeType != Node.ELEMENT_NODE)
				continue
			children++

			if(!hashState.signing && name.length > 3 && name.endsWith("MAC"))
				continue

			val longName = "$pfx.$name"
			val ret = recursiveHash(hashState, longName, node)
			if(ret < 0) return -1
			if(ret > 0) continue

			val nodeVal = node.textContent
			var numBytes = 0
			if(nodeVal.isEmpty()){
				/*
				 * An empty string is valid XML but it might violate
				 * the sdtid format.  We'll handle it the same bizarre
				 * way as RSA just to be safe.
				 */
				val appendStr = "$longName </$name>\n"
				numBytes = appendStr.length
				appendStr.toByteArray().copyInto(hashState.data, hashState.pos, 0, min(remain, numBytes))
			} else {
				val appendStr = "$longName $nodeVal\n"
				numBytes = appendStr.length
				appendStr.toByteArray().copyInto(hashState.data, hashState.pos, 0, min(remain, numBytes))

				/* Bug compatibility :-( */
				val len = numBytes + hashState.padding
				if (!hashState.signing && len <= 16 && len < remain) {
					hashState.pos = hashState.pos and 0xf.inv()
					appendStr.toByteArray().copyInto(hashState.data, hashState.pos, 0, min(remain,numBytes))
					hashState.data.fill(0, hashState.pos, hashState.pos + hashState.padding)
				}
			}

			if(numBytes >= remain)
				return -1

			/*
			 * This doesn't really make sense but it's required for
			 * compatibility
			 */
			hashState.pos += numBytes + hashState.padding
			if(!hashState.signing) {
				if(hashState.pos and 0xF > 0)
					hashState.padding = hashState.pos and 0xF
				else
					hashState.padding = 0x10
			}
		}
		return children
	}
}
