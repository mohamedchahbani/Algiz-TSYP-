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
import { useNavigate } from 'react-router-dom';
import TemporaryDrawer from './TemporaryDrawer';

function AddUser() {
  const [macAddress, setMacAddress] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [severity, setSeverity] = useState('');
  const [open, setOpen] = useState(false);

  const navigate = useNavigate();

  const handleSubmit = (event) => {
    event.preventDefault();
    setOpen(true); // Set `open` to true every time the form is submitted
    // You can add logic here to validate or save the new user
    setMessage('User added successfully');
    setSeverity('success');
    setUsername('');
    setPassword('');
    setMacAddress('');
    // Navigate to another page if needed
    // navigate('Dashboard');
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
            Add User
          </Typography>
          <Box component='form' onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              label='MAC Address'
              variant='outlined'
              fullWidth
              margin='normal'
              value={macAddress}
              onChange={(e) => setMacAddress(e.target.value)}
            />
            <TextField
              label='Username'
              variant='outlined'
              fullWidth
              margin='normal'
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <TextField
              label='Password'
              variant='outlined'
              fullWidth
              type='password'
              margin='normal'
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <Button
              type='submit'
              fullWidth
              variant='contained' 
              color='primary'
              sx={{ mt: 2 }}
            >
              Add User
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

export default AddUser;
