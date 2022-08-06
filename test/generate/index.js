const Common = require('@ethereumjs/common').default;
const { Chain, Hardfork } = require('@ethereumjs/common')
const { AccessListEIP2930Transaction, Transaction } = require('@ethereumjs/tx');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { randomBytes } = require('crypto');
const fs = require('fs');

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Berlin });

const LEGACY = 'legacy';
const ACCESS_LIST = 'accesslist';
const ACCESS_LIST_TYPE = "0x01";

const params = yargs(hideBin(process.argv))
  .option('random', {
    alias: 'r',
    type: 'boolean',
    description: 'If true, random transactions will be generated and signed',
		demandOption: true,
		default: false
  })
  .option('type', {
    alias: 't',
    type: 'string',
    description: 'Type of transaction',
		demandOption: true,
		default: 'legacy',
		choices: [LEGACY, ACCESS_LIST]
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
		return fileScenarios(params);
	} else {
		console.error('Either --file or --random is required');
		process.exit(1);
	}
}

function randomScenarios({ number, type }) {
	let scenarios = [];
	for (let i = 0; i < number; i++) {
		scenarios.push(randomScenario(type));
	}
	return scenarios;
}

function fileScenarios({ file }) {
	const contents = JSON.parse(fs.readFileSync(file, 'utf8'));
	return Array.isArray(contents) ? contents : [contents];
}

function randomScenario(type) {
	// TODO make this support all transactions
	
	if (type === LEGACY) {
		return {
			transaction: {
				data: randomBytes(1024),
				gasLimit: randHexInt(0xFFFFFFFF),
				gasPrice: randHexInt(0xFFFFFFFF),
				nonce: randHexInt(0xFFFFF),
				to: '0x' + randomBytes(20).toString('hex'),
				value: Number.MAX_SAFE_INTEGER,
				chain: 0x01,
			},
			privateKey: '0x' + randomBytes(32).toString('hex')
		};
	} else {
		const accessList = [];

		for (let i = 0; i < 1 + Math.floor(randInt(10)); i++) {
			const address = '0x' + randomBytes(20).toString('hex');
			const storageKeys = [];
			
			for (let j = 0; j < 1 + Math.floor(randInt(5)); j++) {
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
				"chain": 0x01,
				accessList,
				"type": ACCESS_LIST_TYPE
			},
			privateKey: '0x' + randomBytes(32).toString('hex')
		};
	}
}

function randHexInt(n) {
	return randInt(n);//.toString(16);
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

function processScenario(params) {
	let { transaction, privateKey } = params;
	if (params.input) {
		transaction = params.input;
	}
	const originalPrivateKey = privateKey;
	let tx;
	if (!!transaction.gas) {
		throw new Error('Transaction requires gas');
	}
	if (transaction.type === '0x01') {
		tx = AccessListEIP2930Transaction.fromTxData(transaction, { common });
	} else {
		tx = Transaction.fromTxData(transaction, { common });
	}

	privateKey = Buffer.from(
		privateKey.replace('0x', ''),
		'hex',
	);

	const signedTx = tx.sign(privateKey);
	const hash = '0x'+ signedTx.getMessageToSign().toString('hex');
	const rawUnsigned  = signedTx.getMessageToSign(false).toString('hex')
	const v = parseInt(signedTx.v.toString());

	const vrs = {
			v: v,
			r: '0x' + signedTx.r.toBuffer('bigendian', 32).toString('hex'),
			s: '0x' + signedTx.s.toBuffer('bigendian', 32).toString('hex'),
	};

	return {
		input: {
			...transaction
		},
		privateKey: originalPrivateKey,
		output: {
			...vrs,
			hash,
			rawUnsigned,
			bytes: '0x' + signedTx.serialize().toString('hex')
		}
	};
}

// now actually do the stuff!

const scenarios = getScenarios(params);
let processedScenarios = processScenarios(scenarios);
for (let s of processedScenarios) {
	s.input.data = '0x' + s.input.data.toString('hex');
	s.input.gas = s.input.gasLimit;
	//delete s.input.gasLimit;
}
if (processedScenarios.length === 1) {
	processedScenarios = processedScenarios[0];
}

console.log(JSON.stringify(processedScenarios, (k, x) => Buffer.isBuffer(x) ? '0x' + x.toString('hex'): x, 2));
