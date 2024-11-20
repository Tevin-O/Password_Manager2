"use strict";

import { expect } from 'chai';
import Keychain from '../pm_main.js';

async function expectReject(promise) {
    try {
        await promise;
        throw new Error("Expected failure, but function succeeded.");
    } catch (error) {
        // Test passes if error is thrown
    }
}

describe('Password manager', function () {
    this.timeout(5000);
    let password = "password123!";
    let kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', function () {

        it('inits without an error', async function () {
            await Keychain.init(password);
        });

        it('can set and retrieve a password', async function () {
            const keychain = await Keychain.init(password);
            const url = 'www.stanford.edu';
            const pw = 'sunetpassword';
            await keychain.set(url, pw);
            expect(await keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', async function () {
            const keychain = await Keychain.init(password);
            for (const k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            for (const k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', async function () {
            const keychain = await Keychain.init(password);
            for (const k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.get('nonexistent')).to.be.null;
        });

        it('can remove a password', async function () {
            const keychain = await Keychain.init(password);
            for (const k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('service1')).to.be.true;
            expect(await keychain.get('service1')).to.be.null;
        });

        it('returns false if there is no password for the domain being removed', async function () {
            const keychain = await Keychain.init(password);
            expect(await keychain.remove('nonexistent')).to.be.false;
        });

        it('can dump and restore the database', async function () {
            const keychain = await Keychain.init(password);
            for (let i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            const { repr, checksum } = await keychain.dump();
            const parsedContents = JSON.parse(repr);

            expect(parsedContents).to.have.keys('kvs', 'salt');
            const newKeychain = await Keychain.load(password, repr, parsedContents, checksum);

            for (let i = 0; i < 10; i++) {
                expect(await newKeychain.get(String(i))).to.equal(String(i));
            }
        });

        it('fails to restore the database if checksum is wrong', async function () {
            const keychain = await Keychain.init(password);
            for (const k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            const { repr } = await keychain.dump();
            const fakeChecksum = 'invalidchecksum';
            await expectReject(Keychain.load(password, repr, JSON.parse(repr), fakeChecksum));
        });

        it('returns false if trying to load with an incorrect password', async function () {
            const keychain = await Keychain.init(password);
            for (const k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            const { repr, checksum } = await keychain.dump();
            await expectReject(Keychain.load("fakepassword", repr, JSON.parse(repr), checksum));
        });
    });

    describe('security', function () {

        it("doesn't store domain names and passwords in the clear", async function () {
            const keychain = await Keychain.init(password);
            const url = 'www.stanford.edu';
            const pw = 'sunetpassword';

            await keychain.set(url, pw);
            const { repr } = await keychain.dump();

            expect(repr).not.to.contain(url);
            expect(repr).not.to.contain(pw);
        });

        it('includes a kvs object in the serialized dump', async function () {
            const keychain = await Keychain.init(password);
            for (let i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            const { repr } = await keychain.dump();
            const parsedContents = JSON.parse(repr);

            expect(parsedContents).to.have.keys('kvs', 'salt');
            expect(parsedContents.kvs).to.be.an('object');
            expect(Object.keys(parsedContents.kvs)).to.have.lengthOf(10);
        });
    });
});
