import React, { useState, useEffect } from 'react';
import {
  Box,
  Alert,
  IconButton,
  Collapse,
  LinearProgress,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';

export default function AlertSuccess({ message, severity, open_1, onClose }) {
  const [open, setOpen] = useState(open_1);

  useEffect(() => {
    setOpen(open_1); // Update open state when open_1 changes

    if (open_1) {
      const timer = setTimeout(() => {
        setOpen(false); // Close after 5 seconds
        if (onClose) onClose(); // Call the parent onClose function
      }, 2000);

      // Clear the timer if the component is unmounted or if `open` is manually closed
      return () => clearTimeout(timer);
    }
  }, [open_1, onClose]);

  return (
    <Box sx={{ width: '300px' }}>
      <Collapse in={open}>
        <Alert
          severity={severity}
          action={
            <IconButton
              aria-label='close'
              color='inherit'
              size='small'
              onClick={() => {
                setOpen(false);
                if (onClose) onClose(); // Call onClose when user closes manually
              }}
            >
              <CloseIcon fontSize='inherit' />
            </IconButton>
          }
        >
          {message}
        </Alert>
        <LinearProgress color={severity} />
      </Collapse>
    </Box>
  );
}
