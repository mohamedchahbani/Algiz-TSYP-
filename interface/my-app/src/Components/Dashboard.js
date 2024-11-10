import React from 'react';
import TemporaryDrawer from './TemporaryDrawer';
import AddUser from './AddUser';
import EditAdminCredentials from './EditAdminCredentials';
import Showmachines from './Showmachines_1';

export default function Dashboard() {
  return (
    <div>
      <TemporaryDrawer />
      {/* <AddUser /> */}
      {/* <p>knfksnk</p> */}
      <Showmachines />
    </div>
  );
}
