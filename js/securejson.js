var EC = require('./elliptic/elliptic.min').ec;
var SHA3 = require('./sha3/sha3.min');

// Create and initialize EC context
// (better do it once and reuse it)
var ec = new EC('secp256k1');

// Generate keys
/*
var key = ec.genKeyPair();
prihex = key.getPrivate('hex')
pubhex = key.getPublic(false, 'hex')
*/
console.log(window.performance.now())
//var prihex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
var prihex = SHA3.sha3_256('hahahahahaha');

var keys = ec.keyFromPrivate(prihex, 'hex');
var pubhex = keys.getPublic(false, 'hex');
console.log(prihex.length/2)
console.log(prihex)
console.log(pubhex.length/2);
console.log(pubhex);

pubkey = ec.keyFromPublic(pubhex, 'hex');
prikey = ec.keyFromPrivate(prihex, 'hex');

var msg = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var sig = ec.sign(msg, prikey);
console.log(ec.verify(msg, sig, pubkey));

// Sign the message's hash (input must be an array, or a hex-string)
var msgHash = [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ];
var signature = prikey.sign(msgHash);

// Export DER encoded signature in Array
var derSign = signature.toDER();

// Verify signature
console.log(pubkey.verify(msgHash, derSign));

function GenerageJson(user, passwd, data) {
	var prikey = SHA3.sha3_256(passwd);
	var iv = SHA3.sha3_256(user);
}