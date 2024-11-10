// send_email.js
const express = require('express');
const nodemailer = require('nodemailer');

const router = express.Router();

// Email sending route
router.post('/send_email', (req, res) => {
  console.log(req.body);

  const { from, to, subject, message } = req.body;

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'mohamedchahbaniaze106@gmail.com',
      pass: 'luqsfdigzmgbspsc',
    },
  });

  const mailOptions = {
    from,
    to,
    subject,
    text: message,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error(error);
      res.status(500).send('Error sending email');  
    } else {
      console.log('Email Sent: ' + info.response);
      res.json({ message: 'Email sent successfully' });
    }
  });
});

module.exports = router;
