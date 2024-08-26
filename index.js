const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const secretKey = '1234';

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
    host: 'localhost',
    port: 3307,
    user: 'root',
    password: '',
    database: 'crud'
});

db.connect(err => { //funcion callback que se ejecuta solo despues de que db.connect termine su tarea
    if (err) {
        console.error('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to mysql DB');
});


// Función para verificar el token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'Token requerido' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token inválido' });
        }
        req.userId = decoded.userId;
        next();
    });
};


app.post("/register", (req, res) => {
    const { email, password } = req.body;
    const saltRounds = 10;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    console.log(!emailRegex.test(email));
    if(!emailRegex.test(email)){
        return res.status(200).send({message: 'Correo electronico no valido'});
    }

    bcrypt.genSalt(saltRounds, function(err, salt) {
        if (err) {
            return res.status(500).json({ error: 'Error al generar la sal' });
        }

        bcrypt.hash(password, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({ error: 'Error al encriptar la contraseña' });
            }

            // Insertar el usuario en la base de datos
            const sql = 'INSERT INTO user (email, password) VALUES (?, ?)';
            db.query(sql, [email, hash], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: 'Error al guardar el usuario' });
                }
                res.json({ message: 'Usuario añadido!', id: result.insertId });
            });
        });
    });
});

app.post("/login", (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM user WHERE email = ?';

    db.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Error en la base de datos' });
        }
        if (result.length === 0) {
            return res.status(401).json({ error: 'Email no válido' });
        }

        const user = result[0];
        console.log(result);
        console.log(password);
        console.log(user.password);

        bcrypt.compare(password, user.password, function(err, isMatch) { //funcion callback que se ejecuta cuando bcrypt ha realizado la comparasion.
            if (err) {
                return res.status(500).json({ error: 'Error al comparar las contraseñas' });
            }

            if (!isMatch) {
                return res.status(401).json({ error: 'Contraseña incorrecta' });
            }
            
            const token = jwt.sign({userId: user.user_id}, secretKey, {expiresIn: '1h'});
            return res.json({ message: 'Inicio de sesión exitoso!', token: token });
        });
    });
});

app.get("/users", verifyToken, (req, res) => {
    const sql = 'SELECT * FROM user';
    db.query(sql, (err, result) => {
        if (err) {
            throw err;
        }
        res.json(result);
    });
});

app.put("/user/:email", (req, res) => {
    const { email } = req.params;
    const { password } = req.body;
    const saltRounds = 10;

    if (!password) {
        return res.status(400).send({ message: 'Contraseña es requerida' });
    }

    console.log(`Updating password for user with ID: ${email}`); // Agregar este log para depuración

    bcrypt.genSalt(saltRounds, function(err, salt) {
        if (err) {
            return res.status(500).json({ error: 'Error al generar la sal' });
        }

        bcrypt.hash(password, salt, function(err, hash) {
            if (err) {
                return res.status(500).json({ error: 'Error al encriptar la contraseña' });
            }

            const sql = 'UPDATE user SET password = ? WHERE email = ?';
            db.query(sql, [hash, email], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: 'Error al actualizar la contraseña del usuario', details: err.message });
                }
                res.json({ message: 'Contraseña actualizada!' });
            });
        });
    });
});

app.delete("/user/:id", (req,res) => {
    const {id} = req.params; //DESTRUCTURACION DE OBJETOS, ESTO ES EQUIVALENTE A const id = req.params.id
    console.log(id);

    const sql = 'DELETE FROM user WHERE user_id = ?';
    db.query(sql, [id], (err,result) => {
        if(err){
            return res.status(500).json({error: 'Erorr al eliminar usuario', details: err.message});
        }
        if(result.affectedArrows === 0 ){
            return res.status(404).json({ error: 'Este email no está registrado' });
        }
        res.json({message: `Usuario con ID: ${id} eliminado!`})
    })
})


// Ruta protegida
app.get("/protected", verifyToken, (req, res) => {
    res.json({ message: 'Accediste a una ruta protegida!', userId: req.userId });
});

app.listen(4023, () => {
    console.log('node app started.');
});
