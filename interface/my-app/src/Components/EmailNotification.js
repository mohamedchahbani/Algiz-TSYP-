import React, { useState } from 'react';
import {
  TextField,
  Button,
  Box,
  Typography,
  Container,
  Paper,
} from '@mui/material';
import AlertSuccess from './AlertSuccess';
import TemporaryDrawer from './TemporaryDrawer';
import axios from 'axios';

function EmailNotification() {
  const [senderEmail, setSenderEmail] = useState('');
  const [recipientEmail, setRecipientEmail] = useState('');
  const [message, setMessage] = useState('');
  const [severity, setSeverity] = useState('');
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setOpen(true);
    if (senderEmail && recipientEmail) {
      setLoading(true); // Start loading
      try {
        const data = {
          from: senderEmail,
          to: recipientEmail,
          subject: 'Something from back',
          message: 'Something from back',
        };
        console.log('Sending request with data:', data); // Log the data being sent
        const response = await axios.post(
          'http://localhost:3001/send_email',
          data
        );
        console.log('API response:', response); // Log the API response

        if (response.status === 200) {
          setMessage('Email notification sent successfully');
          setSeverity('success');
        } else {
          setMessage('Failed to send email');
          setSeverity('error');
        }
      } catch (error) {
        console.error('Error sending email:', error);
        setMessage('There was an error sending the email');
        setSeverity('error');
      } finally {
        setLoading(false); // Stop loading after the request completes
      }
      setSenderEmail('');
      setRecipientEmail('');
    } else {
      setMessage('Please enter both sender and recipient email');
      setSeverity('error');
      setLoading(false); // Stop loading if inputs are missing
    }
  };

  const handleCloseAlert = () => {
    setOpen(false);
  };

  return (
    <div>
      <TemporaryDrawer />
      <Container
        component='main'
        maxWidth='xs'
        sx={{
          height: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Paper
          elevation={3}
          sx={{
            padding: 4,
            marginTop: 8,
            backgroundColor: 'rgba(255, 255, 255, 0)',
          }}
        >
          <Typography variant='h5' component='h1' align='center'>
            Send Email Notification
          </Typography>
          <Box component='form' onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              label='Sender Email'
              variant='outlined'
              fullWidth
              margin='normal'
              value={senderEmail}
              onChange={(e) => setSenderEmail(e.target.value)}
              inputProps={{
                pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                title: 'Email should be in the format: user@example.com',
              }}
              required
            />
            <TextField
              label='Recipient Email'
              variant='outlined'
              fullWidth
              margin='normal'
              value={recipientEmail}
              onChange={(e) => setRecipientEmail(e.target.value)}
              inputProps={{
                pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                title: 'Email should be in the format: user@example.com',
              }}
              required
            />
            <Button
              type='submit'
              fullWidth
              variant='contained'
              color='primary'
              sx={{ mt: 2 }}
              disabled={loading} // Disable button when loading
            >
              {loading ? 'Sending...' : 'Send Notification'}
            </Button>

            {open && (
              <Box
                sx={{
                  position: 'absolute',
                  top: 20,
                  left: 20,
                  zIndex: 10,
                  width: 'auto',
                }}
              >
                <AlertSuccess
                  message={message}
                  severity={severity}
                  open_1={open}
                  onClose={handleCloseAlert}
                />
              </Box>
            )}
          </Box>
        </Paper>
      </Container>
    </div>
  );
}

export default EmailNotification;
