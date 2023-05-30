const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const cors = require('cors'); // Add CORS middleware for cross-origin requests
const path = require('path'); // Add path module for serving static files
const mongoose = require('mongoose');

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (token == null) {
      return res.sendStatus(401);
    }
  
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      
      req.user = user;
      next();
    });
  }
  

app.use(express.json());
app.use(cors()); // Enable CORS for all routes
app.use(express.static(path.join(__dirname, 'client/build'))); // Serve static files from React build folder

// Connection URI
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.98hdmyg.mongodb.net/?retryWrites=true&w=majority`;

// Connect to the MongoDB server
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to the database');
  })
  .catch((error) => {
    console.error('Failed to connect to the database:', error);
  });

// Define a user schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    password: { type: String, required: true }
  });
  
// Create a user model
const User = mongoose.model('User', userSchema);
  
// A basic user database
const users = [];
// In a real application, you should store refresh tokens in a database
let refreshTokens = [];
// Signup Route
app.post('/signup', async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const user = new User({ name: req.body.name, password: hashedPassword });
  
      // Save the user to the database
      await user.save();
  
      res.status(201).json(user);
    } catch (error) {
      console.error('Failed to create user:', error);
      res.status(500).send();
    }
  });
  
// Login Route
app.post('/login', async (req, res) => {
try {
    const user = await User.findOne({ name: req.body.name });
    if (!user) {
    return res.status(400).send('Cannot find user');
    }

    if (await bcrypt.compare(req.body.password, user.password)) {
    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user.toJSON(), process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);
    res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
    res.send('Not Allowed');
    }
} catch (error) {
    console.error('Failed to login:', error);
    res.status(500).send();
}
});

app.post('/token', (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

// Middleware to Authenticate
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}

// Protected Route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ title: 'This is protected data', user: req.user });
});

// Serve the React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build/index.html'));
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});

process.on('SIGINT', () => {
    mongoose.connection.close(() => {
      console.log('Database connection closed');
      process.exit();
    });
  });