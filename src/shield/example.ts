import express from 'express';
import { NehonixShield } from './Core/NehonixShield';
import { NSHParser } from './Core/NSHParser';
import path from 'path';

async function main() {
  // Create Express app
  const app = express();

  // Load security rules from .nsh files
  const rulesDir = path.join(__dirname, 'rules');
  const rules = await NSHParser.loadDirectory(rulesDir);

  // Create NehonixShield instance with configuration
  const shield = new NehonixShield({
    trustedProxies: ['127.0.0.1'],
    bannedIPs: ['10.0.0.5'],
    bannedRanges: ['192.168.1.0/24'],
    maxPayloadSize: 5000000, // 5MB
    customRules: rules
  });

  // Apply security middleware to Express app
  shield.applyMiddleware(app);

  // routes here
  app.get('/', (req, res) => {
    res.send('Hello, secure world!');
  });

  // Start server
  app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
  });
}

main().catch(console.error);
