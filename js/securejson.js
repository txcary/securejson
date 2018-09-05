var EC = require('./elliptic/elliptic.min').ec;
var SHA3 = require('./sha3/sha3.min');
var CRYPTO = require('./crypto/crypto-js.min');

// Create and initialize EC context
// (better do it once and reuse it)
var ec = new EC('secp256k1');

var out = CRYPTO.AES.encrypt("aaa", "bbb", {mode: CRYPTO.mode.CTR, iv: "aaaa"});
//console.log(out)

var ts = Math.round((new Date()).getTime() / 1000);
console.log(ts);

// Generate keys
/*
var key = ec.genKeyPair();
prihex = key.getPrivate('hex')
pubhex = key.getPublic(false, 'hex')
*/
//console.log(SHA3.shake256("1234", 256))
//console.log(window.performance.now())
//var prihex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
var prihex = SHA3.shake256('1234', 256);

var keys = ec.keyFromPrivate(prihex, 'hex');
var pubhex = keys.getPublic(false, 'hex');
//console.log(prihex.length/2)
//console.log(prihex)
//console.log(pubhex.length/2);
//console.log(pubhex);

pubkey = ec.keyFromPublic(pubhex, 'hex');
prikey = ec.keyFromPrivate(prihex, 'hex');

var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var sig = ec.sign(msg, prikey);
//console.log(ec.verify(msg, sig, pubkey));

// Sign the message's hash (input must be an array, or a hex-string)
var msgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var signature = prikey.sign(msgHash);

// Export DER encoded signature in Array
var derSign = signature.toDER();

// Verify signature
//console.log(pubkey.verify(msgHash, derSign));

function GenerateJson(user, passwd, data) {
	var ec = new EC('secp256k1');

	var prikeyHex = SHA3.shake256(passwd, 256);
	var prikey = ec.keyFromPrivate(prikeyHex, 'hex');
	var pubkeyHex = prikey.getPublic(false, 'hex');
	var pubkey = ec.keyFromPublic(pubkeyHex, 'hex');
	
	var iv = SHA3.shake256(user, 256);
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

function genHash(user, data, time, pubkey) {
	var userHash = SHA3.shake256.array(hexToBytes(user), 256);
	var dataHash = SHA3.shake256.array(hexToBytes(data), 256);
	var timeHash = SHA3.shake256.array(hexToBytes(time), 256);
	var pubkeyHash = SHA3.shake256.array(hexToBytes(pubkey), 256);
	var full = Array();
	//full.concat( hexToBytes(userHash), hexToBytes(dataHash), hexToBytes(timeHash), hexToBytes(pubkeyHash) );
	full.concat( userHash, pubkeyHash, timeHash, dataHash );
	var fullHash = SHA3.shake256.array(full, 256);
	return fullHash
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