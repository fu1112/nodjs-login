const mysql = require("mysql2");
const dbcon = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "nodejs-login"
}).promise()

module.exports = dbcon;