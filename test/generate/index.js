const Common = require('@ethereumjs/common').default;
const { Chain, Hardfork } = require('@ethereumjs/common')
const { AccessListEIP2930Transaction, Transaction, FeeMarketEIP1559Transaction } = require('@ethereumjs/tx');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const { randomBytes } = require('crypto');
const fs = require('fs');

const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Berlin });
const common1559 = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.Merge, eips: [1559] });

const LEGACY = 'legacy';
const ACCESS_LIST = 'accesslist';
const ACCESS_LIST_TYPE = "0x01";
const FEE_MARKET = 'feemarket';
const FEE_MARKET_TYPE = "0x02";

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
		choices: [LEGACY, ACCESS_LIST, FEE_MARKET]
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
	} else if (type === ACCESS_LIST) {
		const accessList = generateRandomAccessList()

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
	} else if (type === FEE_MARKET) {
        const accessList = generateRandomAccessList()

        let maxPriorityFeePerGas = randHexInt(0xFFFFFFFF)
        let maxFeePerGas = randHexInt(0xFFFFFFFF)

        ;[maxPriorityFeePerGas, maxFeePerGas] = maxFeePerGas > maxPriorityFeePerGas ?
          [maxPriorityFeePerGas, maxFeePerGas] : [maxFeePerGas, maxPriorityFeePerGas]

		return {
			transaction: {
				"data": randomBytes(1024),
				"gasLimit": randHexInt(0xFFFFFFFF),
				"maxPriorityFeePerGas": maxPriorityFeePerGas,
				"maxFeePerGas": maxFeePerGas,
				"nonce": randHexInt(0xFFFFF),
				"to": '0x' + randomBytes(20).toString('hex'),
				"value": Number.MAX_SAFE_INTEGER,
				"chain": 0x01,
				accessList,
				"type": FEE_MARKET_TYPE
			},
			privateKey: '0x' + randomBytes(32).toString('hex')
		};
	}
}

function generateRandomAccessList() {
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

  return accessList
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
    transaction.gasLimit = transaction.gas || transaction.gasLimit
	if (transaction.type === '0x01') {
		tx = AccessListEIP2930Transaction.fromTxData(transaction, { common });
	} else if (transaction.type === '0x02') {
		tx = FeeMarketEIP1559Transaction.fromTxData(transaction, { common: common1559 });
	} else {
		tx = Transaction.fromTxData(transaction, { common });
	}

	privateKey = Buffer.from(
		privateKey.replace('0x', ''),
		'hex',
	);

	const signedTx = tx.sign(privateKey);
	const hash = '0x'+ signedTx.getMessageToSign().toString('hex');
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
			bytes: '0x' + signedTx.serialize().toString('hex')
		}
	};
}

// now actually do the stuff!

const scenarios = getScenarios(params);
let processedScenarios = processScenarios(scenarios);
for (let s of processedScenarios) {
	s.input.gas = s.input.gasLimit || s.input.gas;
	delete s.input.gasLimit;
}
if (processedScenarios.length === 1) {
	processedScenarios = processedScenarios[0];
}

console.log(JSON.stringify(processedScenarios, (k, x) => Buffer.isBuffer(x) ? '0x' + x.toString('hex'): x, 2));
