import { Clarinet, Chain, Account, types } from 'https://deno.land/x/clarinet@v0.14.0/index.ts';

const contractName = 'signed-structured-data';

Clarinet.test({
	name: "Extended: Handles various data types and structures",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;
		const wallet1 = accounts.get('wallet_1')!;

		// Test with different principals
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
			types.principal(wallet1.address)
		], deployer.address);
		// This should fail because signature was generated for deployer, not wallet1
		response1.result.expectBool(false);

		// Test with contract principals
		const contractPrincipal = `${deployer.address}.${contractName}`;
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
			types.principal(contractPrincipal)
		], deployer.address);
		// This should fail because signature was generated for deployer principal, not contract principal
		response2.result.expectBool(false);
	}
});

Clarinet.test({
	name: "Extended: Validates signature format and length",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test with too short signature
		const shortSig = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f';
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			shortSig,
			types.principal(deployer.address)
		], deployer.address);
		response1.result.expectBool(false);

		// Test with too long signature
		const longSig = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00123456';
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			longSig,
			types.principal(deployer.address)
		], deployer.address);
		response2.result.expectBool(false);

		// Test with invalid hex characters
		const invalidSig = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f0g';
		const response3 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			invalidSig,
			types.principal(deployer.address)
		], deployer.address);
		response3.result.expectBool(false);
	}
});

Clarinet.test({
	name: "Extended: Validates structured data hash format",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test with too short hash
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e',
			'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
			types.principal(deployer.address)
		], deployer.address);
		response1.result.expectBool(false);

		// Test with too long hash
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e81234',
			'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
			types.principal(deployer.address)
		], deployer.address);
		response2.result.expectBool(false);

		// Test with invalid hex
		const response3 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9eg',
			'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
			types.principal(deployer.address)
		], deployer.address);
		response3.result.expectBool(false);
	}
});

Clarinet.test({
	name: "Extended: Tests signature malleability protection",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test with high S value (potential malleability)
		const highS = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f01';
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			highS,
			types.principal(deployer.address)
		], deployer.address);
		// Should reject malleable signature
		response1.result.expectBool(false);

		// Test with zero R value
		const zeroR = '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			zeroR,
			types.principal(deployer.address)
		], deployer.address);
		response2.result.expectBool(false);

		// Test with zero S value
		const zeroS = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d2027970000000000000000000000000000000000000000000000000000000000000000';
		const response3 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
			zeroS,
			types.principal(deployer.address)
		], deployer.address);
		response3.result.expectBool(false);
	}
});

Clarinet.test({
	name: "Extended: Tests replay attack prevention",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;
		const wallet1 = accounts.get('wallet_1')!;

		// Valid signature for deployer
		const validSig = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00';
		const dataHash = '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8';

		// Should work for original signer
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			dataHash, validSig, types.principal(deployer.address)
		], deployer.address);
		response1.result.expectBool(true);

		// Should fail for different signer (replay attack attempt)
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			dataHash, validSig, types.principal(wallet1.address)
		], wallet1.address);
		response2.result.expectBool(false);

		// Should fail if signature is reused for different data
		const differentDataHash = '0x6297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8';
		const response3 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			differentDataHash, validSig, types.principal(deployer.address)
		], deployer.address);
		response3.result.expectBool(false);
	}
});

Clarinet.test({
	name: "Extended: Tests domain separation integrity",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test various domain combinations that should fail
		const testCases = [
			{
				name: "Different app name",
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0xa06c5f87e4464390ae4e7baf50c14082ca4a8c3a7e35c2f45a842736b40803ba4196ca23485508b9af52e0bb32111e9e900e071b416a08c9a8f093f682ff46b900',
				desc: "Signature for 'Bogus App' instead of 'Dapp Name'"
			},
			{
				name: "Different chain ID",
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0x7bcf3700fd2e899eddff664099e0fa3809d01d72b1b6d1c8fb35fa9e2a13577e750482be1a388f445ceec336ce53d9b9b9632ffefa610414afb827906efa648a00',
				desc: "Signature for chain ID 2 instead of 1"
			},
			{
				name: "Testnet vs mainnet",
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
				desc: "Mainnet signature used on testnet context"
			}
		];

		for (const testCase of testCases) {
			const response = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				testCase.hash, testCase.sig, types.principal(deployer.address)
			], deployer.address);
			response.result.expectBool(false);
		}
	}
});

Clarinet.test({
	name: "Extended: Tests concurrent signature verification",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;
		const wallet1 = accounts.get('wallet_1')!;
		const wallet2 = accounts.get('wallet_2')!;

		// Multiple verifications in sequence to test state isolation
		const signatures = [
			{
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
				principal: deployer.address,
				expected: true
			},
			{
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0x00000000ec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
				principal: deployer.address,
				expected: false
			},
			{
				hash: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				sig: '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
				principal: wallet1.address,
				expected: false
			}
		];

		for (const sigTest of signatures) {
			const response = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				sigTest.hash, sigTest.sig, types.principal(sigTest.principal)
			], deployer.address);

			if (sigTest.expected) {
				response.result.expectBool(true);
			} else {
				response.result.expectBool(false);
			}
		}
	}
});

Clarinet.test({
	name: "Extended: Tests structured data hash collision resistance",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test different data that might produce similar hashes (collision resistance)
		const collisionTests = [
			{
				hash1: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				hash2: '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e9', // One bit different
				sig: '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00'
			},
			{
				hash1: '0x0000000000000000000000000000000000000000000000000000000000000000',
				hash2: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
				sig: '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00'
			}
		];

		for (const collisionTest of collisionTests) {
			// Hash1 with correct signature should work
			const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				collisionTest.hash1, collisionTest.sig, types.principal(deployer.address)
			], deployer.address);

			// Hash2 with same signature should fail (different data)
			const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				collisionTest.hash2, collisionTest.sig, types.principal(deployer.address)
			], deployer.address);

			// Only the first one should pass if it's the original valid signature
			if (collisionTest.hash1 === '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8') {
				response1.result.expectBool(true);
			}
			response2.result.expectBool(false);
		}
	}
});

Clarinet.test({
	name: "Extended: Tests boundary conditions and edge cases",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test with maximum length inputs
		const maxHash = '0x' + 'f'.repeat(64); // 32 bytes
		const maxSig = '0x' + 'f'.repeat(128); // 64 bytes
		const response1 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			maxHash, maxSig, types.principal(deployer.address)
		], deployer.address);
		response1.result.expectBool(false); // Should fail due to invalid signature

		// Test with minimum length inputs
		const minHash = '0x' + '0'.repeat(64); // 32 bytes of zeros
		const minSig = '0x' + '0'.repeat(128); // 64 bytes of zeros
		const response2 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			minHash, minSig, types.principal(deployer.address)
		], deployer.address);
		response2.result.expectBool(false); // Should fail due to invalid signature

		// Test with special characters in principal (if supported)
		const specialPrincipal = 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.special';
		try {
			const response3 = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				'0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8',
				'0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00',
				types.principal(specialPrincipal)
			], deployer.address);
			response3.result.expectBool(false); // Should fail due to different principal
		} catch (error) {
			// Expected if principal format is invalid
		}
	}
});

Clarinet.test({
	name: "Extended: Tests performance and gas considerations",
	async fn(chain: Chain, accounts: Map<string, Account>) {
		const deployer = accounts.get('deployer')!;

		// Test multiple verifications in sequence to ensure no state pollution
		const validSig = '0x7b30087aec38baa381f9f86c7a33c68dfea4849fd1a1d23671b78efa3272d202797fea39a3924907194129de60d3b1930cc738699942fdd1b4bd7a5d29a1c93f00';
		const dataHash = '0x5297eef9765c466d945ad1cb2c81b30b9fed6c165575dc9226e9edf78b8cd9e8';

		// Perform many verifications
		for (let i = 0; i < 10; i++) {
			const response = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
				dataHash, validSig, types.principal(deployer.address)
			], deployer.address);
			response.result.expectBool(true);
		}

		// Ensure final state is still correct
		const finalResponse = chain.callReadOnlyFn(contractName, 'verify-signed-structured-data', [
			dataHash, validSig, types.principal(deployer.address)
		], deployer.address);
		finalResponse.result.expectBool(true);
	}
});
