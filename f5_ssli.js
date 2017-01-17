/*
 * Library to test F5 SSLi site issues
 *
 * This tool will help F5 SSLi and SSLO administrators test
 * websites that are not working.  It will check for common
 * issues with TLS cipher suites and certificate chain trusts
 *
 */

var fs = require('fs');
var https = require('https');
var exports = module.exports = {};
var default_ca_bundle = fs.readFileSync('blended-bundle.crt');
var mod_ca_bundle = fs.readFileSync('mod-blended-bundle.crt');
var default_tmos = "12";
var cipher_suites = JSON.parse(fs.readFileSync('tmos_default_cipher_suites.json', 'utf8'));

/** 
  * Make an HTTPS connection
  *
  * @param {String} address
  * @param {Number} port
  * @param {String} suites
  */
exports.httpsReq = function(address, port, suites, ca_bundle, callback) {
	var options = {
	hostname: address,
	port: port,
	path: '/',
	method: 'GET',
	ca: ca_bundle,
	ciphers: suites
	};

	var req = https.request(options, function(res) {
		callback(res);
	});
	req.on('error', function(e) {
		if (e.message == "unable to get issuer certificate") {
			console.log("Cert Error: " + e.message);
			callback(Error('Unable to verify certificate trust: ' + e.message));	
		} else if (e.message.indexOf("alert handshake failure") > -1) {
			//console.log("Cipher Suite Error: " + e.message);
			callback(Error('Unable to negotiate a TLS cipher suite: ' + e.message));	
		} else {
			console.log("General error" + e.message);
			callback(Error('General error: ' + e.message));	
		}
	});
	req.end();
};

/**
  * check CA Bundle
  *
  * @param {String} address
  * @param {Number} port
  * @param {String} bundle
  * @return {Ojbect} callback
  */
exports.testCA = function(address, port, bundle, callback) {
	switch(bundle) {
		case "blended": 
			var ca_bundle = default_ca_bundle;
			break;
		case "empty": 
			var ca_bundle = mod_ca_bundle;
			break;
		default: 
			var ca_bundle = default_ca_bundle;
	}
	exports.httpsReq(address, port, cipher_suites[default_tmos], ca_bundle, function(res) {
		callback(res);
	});
	
}

/**
  * check Cipher Suites
  *
  * @param {String} address
  * @param {Number} port
  * @param {String} tmos
  * @return {Ojbect} callback
  */
exports.testCiphers = function(address, port, tmos, callback) {
	exports.httpsReq(address, port, cipher_suites[tmos], default_ca_bundle, function(res) {
		callback(res);
	});
	
}