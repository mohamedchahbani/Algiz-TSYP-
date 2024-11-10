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
  CircularProgress,
  Box,
} from '@mui/material';
import { green, red, yellow, grey } from '@mui/material/colors';

const App = () => {
  const [machines, setMachines] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Replace with your API endpoint
    /* axios
      .get('http://your-backend-api/machines')
      .then((response) => {
        setMachines(response.data); 
        setLoading(false);
      })
      .catch((error) => {
        console.error('Error fetching machine data:', error);
        setLoading(false);
      }); */
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
    ];
    setMachines(array);
    setLoading(false);
  }, []);

  const classifyMachine = (ip, username, password) => {
    if (password === 'admin') {
      return { status: 'Vulnerable', color: red[500] };
    } else if (password.length < 8) {
      return { status: 'Weak', color: yellow[600] };
    } else {
      return { status: 'Secure', color: green[500] };
    }
  };

  return (
    <Container maxWidth='lg'>
      <Typography variant='h4' gutterBottom color='primary'>
        LAN Machines Classification
      </Typography>

      {loading ? (
        <Box
          display='flex'
          justifyContent='center'
          alignItems='center'
          height='70vh'
        >
          <CircularProgress />
        </Box>
      ) : (
        <>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
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
                    <TableRow
                      key={index}
                      sx={{
                        '&:nth-of-type(odd)': {
                          backgroundColor: grey[100],
                        },
                        '&:nth-of-type(even)': {
                          backgroundColor: grey[200],
                        },
                      }}
                    >
                      <TableCell>{machine.ip}</TableCell>
                      <TableCell>{machine.username}</TableCell>
                      <TableCell sx={{ color }}>{status}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={2} mt={4}>
            {machines.map((machine, index) => {
              const { status, color } = classifyMachine(
                machine.ip,
                machine.username,
                machine.password
              );
              return (
                <Grid item xs={12} sm={6} md={4} key={index}>
                  <Card sx={{ backgroundColor: grey[50], boxShadow: 3 }}>
                    <CardContent>
                      <Typography variant='h6' color='primary'>
                        {`Machine ${index + 1}`}
                      </Typography>
                      <Typography variant='body1'>IP: {machine.ip}</Typography>
                      <Typography variant='body1'>
                        Username: {machine.username}
                      </Typography>
                      <Typography variant='body1' sx={{ color }}>
                        Status: {status}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        </>
      )}
    </Container>
  );
};

export default App;
