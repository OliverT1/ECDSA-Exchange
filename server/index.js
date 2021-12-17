const express = require('express');
const EC = require('elliptic').ec;
const app = express();
const cors = require('cors');
const port = 3042;
const SHA256 = require('crypto-js/sha256');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

// generate the keys
var ec = new EC('secp256k1');
const keys = []
for (let x = 0; x<3;x++) {
  let key = ec.genKeyPair();
  let publicStr = key.getPublic().encode('hex');
  key.publicKey = publicStr;
  key.privateKey = key.getPrivate().toString(16);

  keys.push(key);
}

keys.forEach((key) => {
  console.log(key.publicKey);
  console.log(key.privateKey);
});

const balances = {
  [keys[0].publicKey] : 100,
  [keys[1].publicKey]: 50,
  [keys[2].publicKey]: 75,
}

app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, signature} = req.body;
  // Check for signature
  const key = ec.keyFromPublic(sender, 'hex');
  const msg = `${amount} to ${recipient}`;
  const msgHash = SHA256(msg).toString();
  if (key.verify(msgHash, signature)){
    console.log("Authorised transaction.");
    balances[sender] -= amount;
    balances[recipient] = (balances[recipient] || 0) + +amount;
    res.send({ balance: balances[sender] });
  }
  else {
    console.log("Incorrect signature, not authorised");
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});
