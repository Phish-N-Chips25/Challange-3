const fs = require('fs');
let t = fs.readFileSync('d:/ISEP/Challange-3/frontend/templates/dashboard.html','utf8');
t = t.replace(/\{\{[^}]+\}\}/g, '"x"');
const m = t.match(/<script>([\s\S]*?)<\/script>/);
fs.writeFileSync(process.env.TEMP + '/dash3.js', m[1]);
console.log('wrote', m[1].length, 'chars');
