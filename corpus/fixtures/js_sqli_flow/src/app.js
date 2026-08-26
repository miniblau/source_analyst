const express = require('express');
const app = express();

// POSITIVE: a query parameter concatenated into SQL.
app.get('/user', (req, res) => {
  const name = req.query.name;
  db.query("select * from users where name = '" + name + "'", (e, r) => res.json(r));
});

// POSITIVE: the same through a helper, one hop.
app.get('/user2', (req, res) => {
  lookup(req.query.name, res);
});
function lookup(name, res) {
  db.query("select * from users where name = '" + name + "'", (e, r) => res.json(r));
}

// NEGATIVE: same sink, value is BOUND as a placeholder.
app.get('/safe', (req, res) => {
  db.query("select * from users where name = ?", [req.query.name], (e, r) => res.json(r));
});

// NEGATIVE: constant only.
app.get('/all', (req, res) => {
  db.query("select * from users where active = 1", (e, r) => res.json(r));
});
