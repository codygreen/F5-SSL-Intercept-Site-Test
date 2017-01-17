var expect = require('chai').expect;
var assert = require('chai').assert;
var ssli = require('../f5_ssli');

var testSite = "api.skype.com";
var testSitePort = 443;

describe("F5 SSLi Site Test Suite", function() {
	describe("F5 TLS Cipher Tests", function() {
		it("Test TLS Ciphers for TMOS 12.0-12.1", function(done) {
			ssli.testCiphers(testSite, testSitePort, "12", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.not.be.an.instanceof(Error);
				done();
			})
		})
		it("Test TLS Ciphers for TMOS 11.6.1", function(done) {
			ssli.testCiphers(testSite, testSitePort, "11.6.1", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.not.be.an.instanceof(Error);
				done();
			})
		})
		it("Test TLS Ciphers for TMOS 11.6.0", function(done) {
			ssli.testCiphers(testSite, testSitePort, "11.6.0", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.not.be.an.instanceof(Error);
				done();
			})
		})
		it("Test TLS Ciphers for TMOS 11.5", function(done) {
			ssli.testCiphers(testSite, testSitePort, "11.5", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.not.be.an.instanceof(Error);
				done();
			})
		})
			it("Test Weak Ciphers", function(done) {
			ssli.testCiphers(testSite, testSitePort, "weak", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.be.an.instanceof(Error);
				done();
			})
		})
	})
	describe("F5 Certificate Bundle Tests", function() {
		it("Test Blended Bundle", function(done) {
			ssli.testCA(testSite, testSitePort, "blended", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.not.be.an.instanceof(Error);
				done();
			})
		})
		it("Test Empty Bundle", function(done) {
			ssli.testCA(testSite, testSitePort, "empty", function(data) {
				assert.isDefined(data);
				expect({data}).to.be.an('object');
				expect(data).to.be.an.instanceof(Error);
				done();
			})
		})
	})
})