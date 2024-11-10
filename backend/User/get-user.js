// routes/get.js
const express = require('express');
const connection = require('../db'); // Import the db connection

const router = express.Router();

// Get admin details route (fetch the admin with id = 1)
router.get('/get-admin', (req, res) => {
  const query = 'SELECT id, username, password FROM admin WHERE id = 1';

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching admin:', err);
      return res.status(500).json({ error: 'Failed to fetch admin' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Respond with the admin details
    res.json({
      id: results[0].id,
      username: results[0].username,
      password: results[0].password,
    });
  });
});

module.exports = router;

