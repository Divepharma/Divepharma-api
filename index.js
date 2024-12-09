// Importar módulos necesarios
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
require('dotenv').config();

// Inicializar la app
const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());

// Configuración de la base de datos
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Clave secreta para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'clave_secreta';

// Rutas

// Registro de usuarios
app.post('/register', async (req, res) => {
  const { nombre_usuario, correo_usuario, contrasena } = req.body;

  try {
    const contrasena_hash = await bcrypt.hash(contrasena, 10);
    const query = `
      INSERT INTO usuarios (nombre_usuario, correo_usuario, contrasena_hash)
      VALUES (?, ?, ?)
    `;
    await db.query(query, [nombre_usuario, correo_usuario, contrasena_hash]);

    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Nombre de usuario o correo ya existe' });
    } else {
      console.error(error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
});

// Login
app.post('/login', async (req, res) => {
  const { correo_usuario, contrasena } = req.body;

  try {
    const [rows] = await db.query('SELECT * FROM usuarios WHERE correo_usuario = ?', [correo_usuario]);

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    }

    const usuario = rows[0];
    const validPassword = await bcrypt.compare(contrasena, usuario.contrasena_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    }

    const token = jwt.sign({ id_usuario: usuario.id_usuario }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Middleware para verificar token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Token no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuarioId = decoded.id_usuario;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

// Ruta protegida
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: `Bienvenido, usuario ${req.usuarioId}` });
});

// Nueva ruta: Obtener todos los usuarios
app.get('/api/usuarios', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT id_usuario, nombre_usuario, correo_usuario FROM usuarios');
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
