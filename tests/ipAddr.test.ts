import assert from "node:assert/strict";
import test from "node:test";

import { normalizeIPAddress } from "../src/ipAddr.ts";

test("normalizeIPAddress renders IPv6 in shortest form", () => {
	assert.equal(normalizeIPAddress("2607:f8b0:4023:0807::5A"), "2607:f8b0:4023:807::5a");
	assert.equal(normalizeIPAddress("2001:0db8:0:0:1:0:0:1"), "2001:db8::1:0:0:1");
	assert.equal(normalizeIPAddress("2001:db8:0:0:1::1"), "2001:db8::1:0:0:1");
	assert.equal(normalizeIPAddress("0:0:0:0:0:0:0:0"), "::");
	assert.equal(normalizeIPAddress("2001:db8:0:1:1:1:1:1"), "2001:db8:0:1:1:1:1:1");
});

test("normalizeIPAddress keeps IPv4 and rejects invalid input", () => {
	assert.equal(normalizeIPAddress("192.0.2.1"), "192.0.2.1");
	assert.equal(normalizeIPAddress("not-an-ip"), null);
	assert.equal(normalizeIPAddress("1::2::3"), null);
	assert.equal(normalizeIPAddress("1:2:3:4:5:6:7:"), null);
	assert.equal(normalizeIPAddress("fe80::1%eth0"), null);
});
