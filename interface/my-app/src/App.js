import { Routes, Route } from 'react-router-dom';
import { Home } from './Components/Home';
import { About } from './Components/About';
import { Navbar } from './Components/Navbar';
import Login from './Components/Login';
import Dashboard from './Components/Dashboard';
import EditAdminCredentials from './Components/EditAdminCredentials';
import AddUser from './Components/AddUser';
import EmailNotification from './Components/EmailNotification';
import './App.css';

function App() {
  return (
    <div className='App'>
      <img
        src='./pic/pic1.png'
        alt='Animated Image'
        className='fade-animation'
      />
      <Routes>
        <Route path='/' element={<Login />} />
        <Route path='/about' element={<About />} />
        <Route path='/Dashboard' element={<Dashboard />} />
        <Route
          path='/EditAdminCredentials'
          element={<EditAdminCredentials />}
        />
        <Route path='/AddUser' element={<AddUser />} />
        <Route path='/EmailNotification' element={<EmailNotification />} />

        {/* Add more routes here */}
      </Routes>
    </div>
  );
}

export default App;
