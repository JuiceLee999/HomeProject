const { Database } = require('node-sqlite3-wasm');
const path = require('path');
const db = new Database(path.join(__dirname, 'db/cache.db'));
db.run("DELETE FROM users WHERE email IN ('test@test.com','test2@test.com')");
db.run('DELETE FROM items WHERE user_id NOT IN (SELECT id FROM users)');
const rows = db.all('SELECT id, email FROM users');
console.log('Remaining users:', JSON.stringify(rows));
db.close();
process.exit(0);
