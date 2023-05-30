import { useState } from 'react';

function App() {
  const [message, setMessage] = useState('');
  const [accessToken, setAccessToken] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSignup = async () => {
    const response = await fetch('/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: username, password: password })
    });

    if (response.ok) {
      const user = await response.json();
      setMessage(`User '${user.name}' signed up successfully!`);
    } else {
      setMessage('Signup failed!');
    }
  };

  const handleLogin = async () => {
    const response = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: username, password: password })
    });

    if (response.ok) {
      const data = await response.json();
      setAccessToken(data.accessToken);
      setMessage('Login successful!');
    } else {
      setMessage('Login failed!');
    }
  };

  const handleProtected = async () => {
    const response = await fetch('/protected', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (response.ok) {
      const data = await response.json();
      setMessage(`Protected data: ${data.title}`);
    } else {
      setMessage('Access denied!');
    }
  };

  return (
    <div>
      <div>
        <label>Username:</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <div>
        <label>Password:</label>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <div>
        <button onClick={handleSignup}>Signup</button>
        <button onClick={handleLogin}>Login</button>
        <button onClick={handleProtected}>Protected Data</button>
      </div>
      <p>{message}</p>
    </div>
  );
}

export default App;
