// app.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Import cors

// Import the routes
const update_admin = require('./admin/update-admin');
const get_admin = require('./admin/get-admin');
const send_email = require('./email/send_email'); // Import the send_email route
const connection = require('./db'); // Import the db connection

const app = express();
const port = 3001;

// Middleware to parse JSON body data
app.use(bodyParser.json());

// Enable CORS for all routes
app.use(cors());

// Use the routes
app.use(update_admin);
app.use(get_admin);
app.use(send_email); // Add the email sending route

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
