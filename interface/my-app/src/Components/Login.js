import React, { useState, useEffect } from 'react';
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
import axios from 'axios';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [severity, setSeverity] = useState('');
  const [open, setOpen] = useState(false);
  const [trueusername, setTrueName] = useState('');
  const [truepass, setTruePass] = useState('');
  const navigate = useNavigate();
  useEffect(() => {
    const fetchAdmin = async () => {
      try {
        const response = await axios.get('http://localhost:3001/get-admin');
        setTrueName(response.data.username);
        setTruePass(response.data.password);
      } catch (error) {
        console.log('There was an error fetching the admin data:', error);
      }
    };

    fetchAdmin();
  }, []);

  const handleSubmit = (event) => {
    event.preventDefault();
    setOpen(true); // Set `open` to true every time the form is submitted
    if (username === trueusername && password === truepass) {
      setMessage('Login successful');
      setSeverity('success');
      navigate('Dashboard');
    } else {
      setMessage('Invalid username or password');
      setSeverity('error');
    }
  };

  // Function to handle closing of the alert
  const handleCloseAlert = () => {
    setOpen(false);
  };

  return (
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
          Login
        </Typography>
        <Box component='form' onSubmit={handleSubmit} sx={{ mt: 2 }}>
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
            Login
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
  );
}

export default Login;
