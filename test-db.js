require('dotenv').config();
const pool = require('./db');

(async function test(){
  try{
    const [rows] = await pool.query('SELECT 1+1 AS result');
    console.log('OK: connected to MySQL, query result =', rows[0].result);
    process.exit(0);
  }catch(err){
    console.error('ERROR: could not connect to MySQL');
    console.error(err.message || err);
    process.exit(2);
  }
})();
