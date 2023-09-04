const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
require('dotenv').config();
const mysql = require('mysql');

const conn = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
})

const emailEnv = process.env.mailAdmin;

const register = async (req, res) => {

    const { email, password } = req.body

    console.log('Données reçues :', req.body);

    if (!email || !password) {
        return res.status(400).json({
            error: 'Données incorrect'
        })
        return;
    }

    if (email != emailEnv) {
        return res.status(401).json({
            error: 'L\email n\est pas autoriser !'
        })
        return;
    }

    // Fonction pour vérifier si un mot de passe est fort
    function isStrongPassword(password) {
        const lengthCheck = password.length >= 8;
        const lowercaseCheck = /[a-z]/.test(password);
        const uppercaseCheck = /[A-Z]/.test(password);
        const digitCheck = /\d/.test(password);
        const specialCharCheck = /[@$!%*?&]/.test(password);

        return lengthCheck && lowercaseCheck && uppercaseCheck && digitCheck && specialCharCheck;
    }

    // Vérification du mot de passe
    if (!isStrongPassword(password)) {
        let errorMessage = 'Le mot de passe doit contenir';

        if (password.length < 8) {
            errorMessage += ' au moins 8 caractères';
        }

        if (!/[A-Z]/.test(password)) {
            errorMessage += ' au moins une majuscule';
        }

        if (!/[a-z]/.test(password)) {
            errorMessage += ' au moins une minuscule';
        }

        if (!/\d/.test(password)) {
            errorMessage += ' au moins un chiffre';
        }

        if (!/[@$!%*?&]/.test(password)) {
            errorMessage += ' au moins un caractère spécial';
        }

        res.status(402).json({
            message: errorMessage
        });

        return;
    }

    // Si le mot de passe est valide, hacher avec bcrypt
    const passwordHash = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO `admin`(`email`, `password`) VALUES (?, ?)';
    conn.query(query, [email, passwordHash], (err) => {
        if (err) {
            console.error('erreur')
            res.status(500).json({ error: 'erreur' })
        } else {
            res.status(200).json({ message: 'utilisateur enregistré' });
        }
    })
}

const login = (req, res) => {

    const { email, password } = req.body

    if (email != emailEnv) {
        return res.status(401).json({
            error: 'L\email n\est pas autoriser !'
        })
        return;
    }

    if (password) {

    }

}

//Routes
module.exports = {
    register,
}