const Common = require('@ethereumjs/common').default;
const { Chain, Hardfork } = require('@ethereumjs/common')
const { AccessListEIP2930Transaction } = require('@ethereumjs/tx');

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Berlin })

const txData = {
}

const scenario = {
	transaction: {
		"data": "0x1a8451e600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"gasLimit": "0x02625a00",
		"gasPrice": "0x01",
		"nonce": "0x00",
		"to": "0xcccccccccccccccccccccccccccccccccccccccc",
		"value": "0x0186a0",
		//"v": "0x01",
		//"r": "0xafb6e247b1c490e284053c87ab5f6b59e219d51f743f7a4d83e400782bc7e4b9",
		//"s": "0x479a268e0e0acd4de3f1e28e4fac2a6b32a4195e8dfa9d19147abe8807aa6f64",
		"chainId": "0x01",
		"accessList": [
			{
				"address": "0x0000000000000000000000000000000000000101",
				"storageKeys": [
					"0x0000000000000000000000000000000000000000000000000000000000000000",
					"0x00000000000000000000000000000000000000000000000000000000000060a7"
				]
			}
		],
		"type": "0x01"
	},
	"privateKey": '0xe331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109'
};

//const tx = AccessListEIP2930Transaction.fromTxData(scenario.transaction, { common })
//const signedTx = tx.sign(privateKey);

function processScenario({ transaction, privateKey }) {
	const tx = AccessListEIP2930Transaction.fromTxData(transaction, { common })
	privateKey = Buffer.from(
		scenario.privateKey.replace('0x', ''),
		'hex',
	);

	const signedTx = tx.sign(privateKey);
	return {
		input: {
			...transaction
		},
		privateKey: {
		},
		output: {
			v: '0x' + signedTx.v,
			r: '0x' + signedTx.r,
			s: '0x' + signedTx.s,
			bytes: '0x' + signedTx.serialize().toString('hex')
		}
	};
}

const processedScenario = processScenario(scenario);

const results = {
	'Transaction to 0xcccccccccccccccccccccccccccccccccccccccc with access list': processedScenario
};

console.log(JSON.stringify(results, null, 2));
