// start-all.js
const { spawn } = require('child_process');

const services = [
  { route: 'd', port: 5003 },
  { route: 'c', port: 5002, upstream: 'http://localhost:5003/d' },
  { route: 'b', port: 5001, upstream: 'http://localhost:5002/c' },
  { route: 'a', port: 5000, upstream: 'http://localhost:5002/c' },
];

services.forEach(({ route, port, upstream }) => {
  const args = ['service.js', route, port.toString()];
  if (upstream) args.push(upstream);

  const proc = spawn('node', args, { stdio: 'inherit' });

  proc.on('exit', code => {
    console.log(`Service ${route.toUpperCase()} exited with code ${code}`);
  });
});

