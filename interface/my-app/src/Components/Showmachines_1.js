import React, { useEffect, useState } from 'react';
import {
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Badge,
  Box,
  CircularProgress,
} from '@mui/material';
import { green, red, orange } from '@mui/material/colors';

const App = () => {
  const [machines, setMachines] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulating API response
    const array = [
      {
        ip: '192.168.1.2',
        username: 'admin',
        password: 'admin',
      },
      {
        ip: '192.168.1.3',
        username: 'user1',
        password: 'strongpassword123',
      },
      {
        ip: '192.168.1.4',
        username: 'guest',
        password: 'guestpassword',
      },
      {
        ip: '192.168.1.2',
        username: 'admin',
        password: 'admin',
      },
      {
        ip: '192.168.1.3',
        username: 'user1',
        password: 'strongpassword123',
      },
      {
        ip: '192.168.1.4',
        username: 'guest',
        password: 'guestpassword',
      },
      {
        ip: '192.168.1.2',
        username: 'admin',
        password: 'admin',
      },
      {
        ip: '192.168.1.3',
        username: 'user1',
        password: 'strongpassword123',
      },
      {
        ip: '192.168.1.4',
        username: 'guest',
        password: 'guestpassword',
      },
    ];
    setMachines(array);
    setLoading(false);
  }, []);

  const classifyMachine = (ip, username, password) => {
    // Classifying based on password strength
    if (password === 'admin') {
      return { status: 'Vulnerable', color: red[500] }; // Red for vulnerable
    } else if (password.length < 12) {
      return { status: 'Weak', color: orange[500] }; // Orange for weak
    } else {
      return { status: 'Secure', color: green[500] }; // Green for secure
    }
  };

  return (
    <Container>
      <Typography
        variant='h4'
        gutterBottom
        sx={{ textAlign: 'center', color: '#3f51b5' }}
      >
        LAN Machines Classification
      </Typography>
      {loading ? (
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            height: '80vh',
          }}
        >
          <CircularProgress size={60} />
        </Box>
      ) : (
        <>
          <TableContainer component={Paper} sx={{ marginBottom: 4 }}>
            <Table>
              <TableHead sx={{ backgroundColor: '#f5f5f5' }}>
                <TableRow>
                  <TableCell>IP Address</TableCell>
                  <TableCell>Username</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {machines.map((machine, index) => {
                  const { status, color } = classifyMachine(
                    machine.ip,
                    machine.username,
                    machine.password
                  );
                  return (
                    <TableRow key={index}>
                      <TableCell>{machine.ip}</TableCell>
                      <TableCell>{machine.username}</TableCell>
                      <TableCell>
                        <Badge
                          badgeContent={status}
                          color='primary'
                          sx={{
                            backgroundColor: color,
                            padding: '0.5em',
                            borderRadius: '8px',
                            color: '#fff',
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>

          {/* <Grid container spacing={2} mt={4}>
            {machines.map((machine, index) => {
              const { status, color } = classifyMachine(
                machine.ip,
                machine.username,
                machine.password
              );
              return (
                <Grid item xs={12} sm={6} md={4} key={index}>
                  <Card
                    sx={{
                      border: `2px solid ${color}`,
                      boxShadow: 3,
                      '&:hover': { boxShadow: 6 },
                    }}
                  >
                    <CardContent>
                      <Typography variant='h6' sx={{ color: '#3f51b5' }}>
                        {`Machine ${index + 1}`}
                      </Typography>
                      <Typography
                        variant='body1'
                        sx={{ marginBottom: '0.5em' }}
                      >
                        <strong>IP:</strong> {machine.ip}
                      </Typography>
                      <Typography
                        variant='body1'
                        sx={{ marginBottom: '0.5em' }}
                      >
                        <strong>Username:</strong> {machine.username}
                      </Typography>
                      <Typography
                        variant='body1'
                        sx={{ marginBottom: '0.5em', color }}
                      >
                        <strong>Status:</strong> {status}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid> */}
        </>
      )}
    </Container>
  );
};

export default App;
