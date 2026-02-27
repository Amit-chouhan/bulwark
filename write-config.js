// Helper: generates ecosystem.config.js from env vars
// Usage on AWS:
//   export MP=chester2026
//   export DP=5q9ra4lLpViYvKZ5
//   export VP=dnlBcmk5wzO7Hins
//   node write-config.js

const fs = require('fs');

const mp = process.env.MP || 'changeme';
const dp = process.env.DP || '';
const vp = process.env.VP || '';

const devHost = 'aws-1-us-east-1.pooler.supabase.com';
const devRef = 'postgres.flzccsvxzmpqglijrcxq';
const vpsHost = 'aws-0-us-west-2.pooler.supabase.com';
const vpsRef = 'postgres.qoobpabjcpshnhpwlztx';

const config = `module.exports = {
  apps: [{
    name: 'dev-monitor',
    script: 'server.js',
    env: {
      MONITOR_PASS: '${mp}',
      DATABASE_URL: 'postgresql://${devRef}:${dp}@${devHost}:6543/postgres',
      VPS_DATABASE_URL: 'postgresql://${vpsRef}:${vp}@${vpsHost}:6543/postgres'
    }
  }]
};
`;

fs.writeFileSync('ecosystem.config.js', config);
console.log('Created ecosystem.config.js');
console.log('  MONITOR_PASS:', mp);
console.log('  DATABASE_URL: set' + (dp ? ' ✓' : ' ✗ (missing DP)'));
console.log('  VPS_DATABASE_URL: set' + (vp ? ' ✓' : ' ✗ (missing VP)'));
