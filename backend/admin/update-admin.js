// routes/update.js
const express = require('express');
const connection = require('../db'); // Import the db connection

const router = express.Router();

// Update admin details route
router.put('/update-admin', (req, res) => {
  const { username, password } = req.body;

  // Check if username and password are provided
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'Username and password are required' });
  }

  // SQL query to update the admin with id = 1
  const query = 'UPDATE admin SET username = ?, password = ? WHERE id = 1';

  connection.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Error updating admin:', err);
      return res.status(500).json({ error: 'Failed to update admin' });
    }

    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.json({ message: 'Admin updated successfully' });
  });
});


module.exports = router;
