const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const cors = require('cors'); // Dodaj middleware CORS dla żądań międzydomenowych
const path = require('path'); // Dodaj moduł path do serwowania plików statycznych
const mongoose = require('mongoose');
require('dotenv').config();

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
app.use(cors());
app.use(express.static(path.join(__dirname, 'client/build'))); // Serwuj pliki statyczne z folderu build Reacta

// URI połączenia z bazą danych
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.98hdmyg.mongodb.net/?retryWrites=true&w=majority`;

// Serwer MongoDB
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Połączono z bazą danych');
  })
  .catch((error) => {
    console.error('Błąd podczas łączenia z bazą danych:', error);
  });

// Schemat użytkownika
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    password: { type: String, required: true }
});

// Model użytkownika
const User = mongoose.model('User', userSchema);


// W rzeczywistej aplikacji powinieneś przechowywać tokeny odświeżające w bazie danych
let refreshTokens = [];

// Trasa rejestracji
app.post('/signup', async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const user = new User({ name: req.body.name, password: hashedPassword });
  
      // Zapisz użytkownika w bazie danych
      await user.save();
  
      res.status(201).json(user);
    } catch (error) {
      console.error('Błąd podczas tworzenia użytkownika:', error);
      res.status(500).send();
    }
});

// Trasa logowania
app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ name: req.body.name });
    if (!user) {
      return res.status(400).send('Nie można znaleźć użytkownika');
    }

    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user.toJSON(), process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.send('Nieautoryzowany');
    }
  } catch (error) {
    console.error('Błąd logowania:', error);
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

// Middleware do uwierzytelniania
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
  return jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}

// Trasa chroniona
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ title: 'To są chronione dane', user: req.user });
});

// Serwuj pliki produkcyjne
app.use(express.static('client/dist'));

// Serwuj aplikację Reacta
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'client', 'dist', 'index.html'));
});

// Uruchom serwer
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Serwer nasłuchuje na porcie ${port}`);
});

process.on('SIGINT', () => {
  mongoose.connection.close(() => {
    console.log('Zamknięto połączenie z bazą danych');
    process.exit();
  });
});
