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

function EditAdminCredentials() {
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');
  const [severity, setSeverity] = useState('');
  const [open, setOpen] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setOpen(true);
    // Check if the new username and password are not empty and update the admin credentials
    if (newUsername && newPassword) {
      try {
        const response = await axios.put('http://localhost:3001/update-admin', {
          username: newUsername,
          password: newPassword,
        });
        setMessage('Admin credentials updated successfully');
        setSeverity('success');
      } catch (error) {
        console.error('There was an error updating the admin data:', error);
        setMessage('Please enter both username and password');
        setSeverity('error');
      }
    } else {
      setMessage('Please enter both username and password');
      setSeverity('error');
    }
  };

  // Function to handle closing of the alert
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
            Edit Admin Credentials
          </Typography>
          <Box component='form' onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              label='New Username'
              variant='outlined'
              fullWidth
              margin='normal'
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              inputProps={{
                pattern: '^[A-Za-z0-9_]{6,255}$', // Allows alphanumeric characters and underscores only, with length between 6 and 255
                title:
                  'Username must be between 6 and 255 characters long and can only contain letters, numbers, and underscores.',
              }}
            />

            <TextField
              label='New Password'
              variant='outlined'
              fullWidth
              type='password'
              margin='normal'
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              inputProps={{
                pattern:
                  '(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,255}',
                title:
                  'Password must contain at least 8 characters, including one letter, one number, and one special character.',
              }}
            />
            <Button
              type='submit'
              fullWidth
              variant='contained'
              color='primary'
              sx={{ mt: 2 }}
            >
              Save Changes
            </Button>

            {/* AlertSuccess component with close handler */}
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
                  onClose={handleCloseAlert} // Add this line to handle close
                />
              </Box>
            )}
          </Box>
        </Paper>
      </Container>
    </div>
  );
}

export default EditAdminCredentials;
