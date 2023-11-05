const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: '127.0.0.1', 
  user: 'root', 
  password: '', 
  database: 'practica02' 
});

db.connect((err) => {
  if (err) {
    console.error('Error de conexión a la base de datos MySQL:', err);
  } else {
    console.log('Conexión exitosa a la base de datos MySQL');
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: '791294843302-i2kbk1962l2e6ljggvrs04bpjduc5ept.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: 'http://localhost:9000/listar',
    },
    (accessToken, refreshToken, profile, done) => {
      const { id, displayName, emails } = profile;
      const googleUser = {
        displayName: displayName,
        email: emails[0].value,
      };

      // Verifica si el usuario ya existe en la base de datos
      const selectSql = 'SELECT * FROM user WHERE correo = ?';
      db.query(selectSql, [googleUser.email], (err, rows) => {
        if (err) {
          console.error('Error al buscar usuario en la base de datos:', err);
          return done(err);
        }

        if (rows.length > 0) {
          // El usuario ya existe, simplemente redirige
          return done(null, googleUser);
        } else {
          // El usuario no existe, guárdalo en la base de datos
          const insertSql = 'INSERT INTO user (nombre, correo) VALUES (?, ?)';
          db.query(insertSql, [googleUser.displayName, googleUser.email], (insertError, result) => {
            if (insertError) {
              console.error('Error al guardar los datos del usuario:', insertError);
              return done(insertError);
            }
            return done(null, googleUser);
          });
        }
      });
    }
  )
);

// Ruta para iniciar sesión con Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Ruta de redirección después de la autenticación con Google
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Si llegas aquí, la autenticación con Google fue exitosa.
    // Puedes redirigir al usuario a la página de inicio o realizar otras acciones.
    res.redirect('/inicio');
  }
);

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

app.get('/', (req, res) => {
  res.render('login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { nombre, contraseña } = req.body;

  // Verificar las credenciales del usuario en la base de datos
  const sql = 'SELECT * FROM user WHERE nombre = ?';
  db.query(sql, [nombre], (err, result) => {
      if (err) {
          console.error('Error al buscar usuario:', err);
          res.status(500).send('Error interno del servidor');
      } else {
          if (result.length === 0) {
              // El usuario no existe, redirigir al registro
              res.redirect('/registro');
          } else {
              // El usuario existe, verificar la contraseña
              const usuario = result[0];
              bcrypt.compare(contraseña, usuario.contraseña, (error, match) => {
                  if (error) {
                      console.error('Error al comparar contraseñas:', error);
                      res.status(500).send('Error interno del servidor');
                  } else {
                      if (match) {
                          // Contraseña correcta, inicia sesión del usuario
                          // Puedes utilizar sesiones o tokens JWT para manejar la autenticación del usuario.
                          // Luego, redirige a la página de inicio o al panel de control.
                          res.redirect('/listar');
                      } else {
                          // Contraseña incorrecta, redirigir al inicio de sesión
                          res.redirect('/login');
                      }
                  }
              });
          }
      }
  });
});

app.get('/registro', (req, res) => {
  res.render('registro');
});

app.post('/registro', (req, res) => {
  const { nombre, correo, contraseña } = req.body;

  // Verificar si el usuario ya existe en la base de datos
  const sql = 'SELECT * FROM user WHERE nombre = ?';
  db.query(sql, [nombre], (err, result) => {
      if (err) {
          console.error('Error al buscar usuario:', err);
          res.status(500).send('Error interno del servidor');
      } else {
          if (result.length > 0) {
              // El usuario ya existe, redirigir al registro
              res.redirect('/registro');
          } else {
              // El usuario no existe, guardar la información en la base de datos
              bcrypt.hash(contraseña, 10, (error, hash) => {
                  if (error) {
                      console.error('Error al encriptar la contraseña:', error);
                      res.status(500).send('Error interno del servidor');
                  } else {
                      const insertSql = 'INSERT INTO user (nombre, correo, contraseña) VALUES (?,?,?)';
                      db.query(insertSql, [nombre, correo, hash], (insertError, insertResult) => {
                          if (insertError) {
                              console.error('Error al agregar usuario:', insertError);
                              res.status(500).send('Error interno del servidor');
                          } else {
                              // Usuario registrado con éxito, redirige al inicio de sesión
                              res.redirect('/login');
                          }
                      });
                  }
              });
          }
      }
  });
});

app.get('/listar', (req, res) => {
  const sql = 'SELECT * FROM user';
  db.query(sql, (err, usuarios) => {
    if (err) {
      console.error('Error al listar usuarios:', err);
      res.status(500).send('Error interno del servidor');
    } else {
      res.render('usuarios', { usuarios });
    }
  });
});

app.post('/eliminar/:id', (req, res) => {
  const userId = req.params.id;
  const sql = 'DELETE FROM user WHERE id = ?';
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.error('Error al eliminar usuario:', err);
      res.status(500).send('Error interno del servidor');
    } else {
      console.log('Usuario eliminado con éxito');
      res.redirect('/listar'); // Redirige al listado de usuarios
    }
  });
});

// Iniciar el servidor
const PORT = process.env.PORT || 9000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});