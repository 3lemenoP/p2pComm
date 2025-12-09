import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const wasmSrc = path.join(__dirname, '../../wasm-core/pkg');
const wasmDest = path.join(__dirname, '../src/wasm');

// Ensure destination directory exists
if (!fs.existsSync(wasmDest)) {
  fs.mkdirSync(wasmDest, { recursive: true });
}

// Copy all files from pkg/ to src/wasm/
try {
  fs.cpSync(wasmSrc, wasmDest, { recursive: true });
  console.log('✓ WASM files copied to src/wasm/');
} catch (error) {
  console.error('Error copying WASM files:', error);
  process.exit(1);
}
