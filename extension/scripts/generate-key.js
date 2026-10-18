// Utility script to generate an RSA key for the Chrome extension,
// compute the "key" value for manifest.json, and calculate the fixed Chrome Extension ID.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const pemPath = path.resolve(rootDir, 'key.pem');
const manifestSrcPath = path.resolve(rootDir, 'src/manifest.json');

function deriveExtensionId(derPublicKey) {
  const hash = crypto.createHash('sha256').update(derPublicKey).digest('hex').slice(0, 32);
  return hash
    .split('')
    .map((c) => String.fromCharCode(parseInt(c, 16) + 97))
    .join('');
}

function main() {
  const shouldApply = process.argv.includes('--apply');
  let privateKeyPem;
  let derPublicKey;

  if (fs.existsSync(pemPath)) {
    console.log(`\x1b[36m[Info]\x1b[0m Found existing key file at: ${pemPath}`);
    privateKeyPem = fs.readFileSync(pemPath, 'utf8');
    const pubKeyObj = crypto.createPublicKey(privateKeyPem);
    derPublicKey = pubKeyObj.export({ type: 'spki', format: 'der' });
  } else {
    console.log('\x1b[36m[Info]\x1b[0m Generating new 2048-bit RSA key pair...');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    derPublicKey = publicKey;
    privateKeyPem = privateKey;
    fs.writeFileSync(pemPath, privateKeyPem, { mode: 0o600 });
    console.log(`\x1b[32m[Success]\x1b[0m Saved private key to: \x1b[1m${pemPath}\x1b[0m`);
    console.log('\x1b[33m[Warning]\x1b[0m Keep key.pem secure and NEVER commit it to public git repositories!');
  }

  const base64Key = derPublicKey.toString('base64');
  const extensionId = deriveExtensionId(derPublicKey);

  console.log('\n============================================================');
  console.log('       CHROME EXTENSION DETERMINISTIC IDENTITY');
  console.log('============================================================');
  console.log(`\n\x1b[32mDeterministic Extension ID:\x1b[0m\n\x1b[1m${extensionId}\x1b[0m\n`);
  console.log(`\x1b[36mManifest "key" Value:\x1b[0m\n${base64Key}\n`);
  console.log('============================================================\n');

  if (shouldApply) {
    if (fs.existsSync(manifestSrcPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestSrcPath, 'utf8'));
      manifest.key = base64Key;
      fs.writeFileSync(manifestSrcPath, JSON.stringify(manifest, null, 2) + '\n');
      console.log(`\x1b[32m[Success]\x1b[0m Updated "key" in ${manifestSrcPath}`);
      console.log('Run `npm run build` to compile dist/manifest.json.');
    } else {
      console.error(`\x1b[31m[Error]\x1b[0m manifest.json not found at ${manifestSrcPath}`);
    }
  } else {
    console.log('To automatically write this key to src/manifest.json, run:');
    console.log('  \x1b[1mnpm run generate-key -- --apply\x1b[0m\n');
  }
}

main();
