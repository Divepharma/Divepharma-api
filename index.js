const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Crear la conexión a la base de datos
const db = mysql.createConnection({
  host: process.env.MYSQL_HOST, // Cambiar a MYSQL_HOST
  user: process.env.MYSQL_USER, // Cambiar a MYSQL_USER
  password: process.env.MYSQL_PASSWORD, // Cambiar a MYSQL_PASSWORD
  database: process.env.MYSQL_DATABASE, // Cambiar a MYSQL_DATABASE
  port: process.env.MYSQL_PORT, // Cambiar a MYSQL_PORT
});

db.connect(err => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    return;
  }
  console.log('Conectado a la base de datos MySQL');
});

// Inicializa Express
const app = express();
app.use(express.json()); // Para parsear JSON en el cuerpo de las solicitudes

const port = 3000;

// Crear un usuario (registro)
app.post('/api/registro', async (req, res) => {
  const { nombre_usuario, correo_usuario, contrasena } = req.body;

  // Verificar si el correo ya está registrado
  db.query('SELECT * FROM usuarios WHERE correo_usuario = ?', [correo_usuario], async (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error en la base de datos' });
    }
    if (result.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    // Hash de la contraseña
    const contrasena_hash = await bcrypt.hash(contrasena, 10);

    // Insertar nuevo usuario
    db.query('INSERT INTO usuarios (nombre_usuario, correo_usuario, contrasena_hash, estado) VALUES (?, ?, ?, ?)', 
    [nombre_usuario, correo_usuario, contrasena_hash, 'activo'], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error al registrar el usuario' });
      }
      res.status(201).json({ message: 'Usuario registrado exitosamente' });
    });
  });
});

// Iniciar sesión (autenticación)
app.post('/api/login', (req, res) => {
  const { correo_usuario, contrasena } = req.body;

  db.query('SELECT * FROM usuarios WHERE correo_usuario = ?', [correo_usuario], async (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error en la base de datos' });
    }
    if (result.length === 0) {
      return res.status(400).json({ error: 'Correo o contraseña incorrectos' });
    }

    const usuario = result[0];

    // Verificar la contraseña
    const esValido = await bcrypt.compare(contrasena, usuario.contrasena_hash);
    if (!esValido) {
      return res.status(400).json({ error: 'Correo o contraseña incorrectos' });
    }

    // Crear el token JWT
    const token = jwt.sign({ id_usuario: usuario.id_usuario }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Inicio de sesión exitoso', token });
  });
});

// Rutas protegidas por JWT
app.get('/api/protected', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Se requiere autenticación' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token no válido' });
    }

    res.json({ message: 'Acceso autorizado', user: decoded });
  });
});

app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});
