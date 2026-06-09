const express = require('express');
const app = express();
const db = require('./db');

const apiKey = process.env.API_KEY; // 🔒 Fixed by SecurityPro

app.post('/update-user', (req, res) => {
    // This should trigger AST-AUTH-BYPASS because it modifies DB without checking auth
    db.users.update({ id: req.body.id }, { name: req.body.name });
    
    // This should trigger SQL Injection rule
    const query = "SELECT * FROM users WHERE id = " + req.body.id;
    
    res.send("Updated");
});

app.listen(3000);
