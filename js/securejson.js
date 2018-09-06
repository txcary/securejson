var EC = require('./elliptic/elliptic.min').ec;
var SHA3 = require('./sha3/sha3.min');
var AES = require('./aes/index.min')
var BASE64 = require('./base64/base64js.min')

var jsonStr = GenerateJson("MyUser", "1234", "MyData");
console.log(jsonStr);

function bytesToBase64(bytes) {
	return BASE64.fromByteArray(bytes);
}

function base64ToBytes(str) {
	return BASE64.toByteArray(str);
}

function base64ToHex(str) {
	return bytesToHex(base64ToBytes(str));
}

function hexToBase64(hex) {
	return bytesToBase64(hexToBytes(hex));
}

function encrypt(dataBytes, ivBytes, keyBytes) {
	var aesCtr = new AES.ModeOfOperation.ctr(keyBytes, ivBytes);
	var encryptedBytes = aesCtr.encrypt(dataBytes);
	return encryptedBytes;
}

function GenerateJson(user, passwd, data) {
	var ec = new EC('secp256k1');

	var prikeyHex = SHA3.shake256(passwd, 256);
	var prikey = ec.keyFromPrivate(prikeyHex, 'hex');
	var pubkeyHex = prikey.getPublic(false, 'hex');
	var pubkey = ec.keyFromPublic(pubkeyHex, 'hex');
	
	var iv = SHA3.shake256(user, 128);
	var encryptedDataBytes = encrypt(stringToBytes(data), hexToBytes(iv), hexToBytes(prikeyHex));
	var encryptedDataHex = bytesToHex(encryptedDataBytes);
	
	var timestampHex = bytesToHex(intToBytes(getTimestamp()));
	var userHex = bytesToHex(stringToBytes(user));
	
	var fullHash = genHash(userHex, encryptedDataHex, timestampHex, pubkeyHex);
	var sigHex = bytesToHex(prikey.sign(fullHash).toDER());
	var obj = {
		UserName : user,
		Signature : hexToBase64(sigHex),
		EncryptedData : hexToBase64(encryptedDataHex),
		Timestamp : hexToBase64(timestampHex),
		PublicKey : hexToBase64(pubkeyHex)
	};

	jsonStr = JSON.stringify(obj);
	return jsonStr;
}

function getPriKey(prikeyHex) {
	var ec = new EC('secp256k1');
	return 
}

function getPubKey(prikeyHex) {
	var pubhex = keys.getPublic(false, 'hex');
	pubkey = ec.keyFromPublic(pubhex, 'hex');
	return pubkey;
}

function getTimestamp() {
	return Math.round((new Date()).getTime() / 1000);
}

function intToBytes(numb) {
	var bytesLen = 4;
	var bytes = new Array(bytesLen-1);
	for(var i=bytesLen; i>0; i--) {
		bytes[i-1] = numb & 0xff;
		numb = numb>>8;
	}
	return bytes;
}

function genHash(userHex, dataHex, timeHex, pubkeyHex) {
	var userHash = SHA3.shake256.array(hexToBytes(userHex), 256);
	var dataHash = SHA3.shake256.array(hexToBytes(dataHex), 256);
	var timeHash = SHA3.shake256.array(hexToBytes(timeHex), 256);
	var pubkeyHash = SHA3.shake256.array(hexToBytes(pubkeyHex), 256);
	var full = Array();
	full = full.concat( userHash, pubkeyHash, timeHash, dataHash );
	var fullHash = SHA3.shake256.array(full, 256);
	return fullHash
}

function bytesToString(bytes) {
	return AES.utils.hex.fromBytes(bytes);
}

function stringToBytes(str) {
	return AES.utils.utf8.toBytes(str);
}

function hexToBytes(hex) {
	var len = hex.length;
	if(len%2!=0) {
		console.log("Error: hexToBytes() length not correct!")
		return null;
	}
	len /= 2;
	var bytes = new Array();
	var pos = 0;
	for(var i=0; i<len; i++) {
		var s = hex.substr(pos,2);
		var v = parseInt(s, 16);
		bytes.push(v);
		pos += 2;
	}
	return bytes;
}

function bytesToHex(bytes) {
	var hex = "";
	for(var i=0; i<bytes.length; i++) {
		var str = bytes[i].toString(16);
		if(str.length==1) {
			str = "0"+ str;
		}
		hex += str;
	}
	return hex;
}
