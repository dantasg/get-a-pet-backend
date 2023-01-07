const express = require('express');
const cors = require('cors');

const conn = require('./db/conn');

const app = express();

// config json response
app.use(express.json());

// Solve cors
app.use(
  cors({
    credentials: true,
    origin: 'http://localhost:3000',
  }),
);

// Public folder for images
app.use(express.static('public'));

// Routes - Users
const UserRoutes = require('./routes/UserRoutes');
app.use('/users', UserRoutes);

// Routes - Pet
const PetRoutes = require('./routes/PetRouter');
app.use('/pets', PetRoutes);

// Routes
app.listen(5000, () => {
  console.log('Servidor rodando!');
});
