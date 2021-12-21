var mysql = require('mysql');

function createCon(){
    var connection  = mysql.createPool({
        connectionLimit: 4000,
        queueLimit: 3000,
        host: 'db',
        user: 'encontact',
        password: '',
        database: 'encontact',
        port: 3306,
        insecureAuth: true
    });

    return connection;
}

module.exports = createCon;
