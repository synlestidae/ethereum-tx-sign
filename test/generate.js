const Common = require('@ethereumjs/common').default;
const { Chain, Hardfork } = require('@ethereumjs/common')
const { AccessListEIP2930Transaction } = require('@ethereumjs/tx');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { randomBytes } = require('crypto');

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Berlin });

//const results = processScenario(randomScenario());

const params = yargs(hideBin(process.argv))
  .option('random', {
    alias: 'r',
    type: 'boolean',
    description: 'If true, random transactions will be generated and signed',
		demandOption: true,
		default: false
  })
  .option('number', {
    alias: 'n',
    type: 'number',
		default: 10,
    description: 'If --random is used, this is how many random transactions are desired' ,
		demandOption: true,
  })
  .option('file', {
    alias: 'f',
    type: 'string',
    description: 'If --random is not used, the file from which to read input transactions' ,
		demandOption: false,
  })
	.help()
	.argv;

function getScenarios(params) {
	if (params.random) {
		return randomScenarios(params);
	} else if (params.file) {
		console.error('Sorry, --file is not yet implemented');
		process.exit(1);
	} else {
		console.error('Either --file or --random is required');
		process.exit(1);
	}
}

function randomScenarios({ number }) {
	let scenarios = [];
	for (let i = 0; i < number; i++) {
		scenarios.push(randomScenario());
	}
	return scenarios;
}

function randomScenario() {
	// TODO make this support all transactions

	const accessList = [];

	for (let i = 0; i < randInt(10); i++) {
		const address = '0x' + randomBytes(20).toString('hex');
		const storageKeys = [];
		
		for (let i = 1; i < randInt(5); i++) {
			storageKeys.push('0x' + randomBytes(32).toString('hex'));
		}

		accessList.push({
			address,
			storageKeys
		});
	}

	return {
		transaction: {
			"data": randomBytes(1024),
			"gasLimit": randHexInt(0xFFFFFFFF),
			"gasPrice": randHexInt(0xFFFFFFFF),
			"nonce": randHexInt(0xFFFFF),
			"to": '0x' + randomBytes(20).toString('hex'),
			"value": Number.MAX_SAFE_INTEGER,
			"chainId": '0x01',
			accessList,
			"type": "0x01"
		},
		"privateKey": '0x' + randomBytes(32).toString('hex')
	};
}

function randHexInt(n) {
	return '0x' + randInt(n).toString(16);
}

function randInt(n) {
	return Math.floor(Math.random() * n)
}

function processScenarios(scenarios) {
	const processedScenarios = [];

	for (let scenario of scenarios) {
		processedScenarios.push(processScenario(scenario));
	}

	return processedScenarios;
}

function processScenario({ transaction, privateKey }) {
	const originalPrivateKey = privateKey;
	const tx = AccessListEIP2930Transaction.fromTxData(transaction, { common })
	privateKey = Buffer.from(
		privateKey.replace('0x', ''),
		'hex',
	);

	const signedTx = tx.sign(privateKey);
	return {
		input: {
			...transaction
		},
		privateKey: originalPrivateKey,
		output: {
			v: '0x' + signedTx.v,
			r: '0x' + signedTx.r,
			s: '0x' + signedTx.s,
			bytes: '0x' + signedTx.serialize().toString('hex')
		}
	};
}

// now actually do the stuff!

const scenarios = getScenarios(params);
const processedScenarios = processScenarios(scenarios);
for (let s of processedScenarios) {
	s.input.data = '0x' + s.input.data.toString('hex');
}

console.log(JSON.stringify(processedScenarios, (k, x) => Buffer.isBuffer(x) ? '0x' + x.toString('hex'): x, 2));
