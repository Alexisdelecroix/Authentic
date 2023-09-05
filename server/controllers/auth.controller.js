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
const KEY = process.env.keyHash

const register = async (req, res) => {

    const { email, password } = req.body


    console.log('Données reçues :', req.body);

    // if (!email || !password) {
    //     return res.status(400).json({
    //         error: 'Données incorrect'
    //     })
    //     return;
    // }

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

const login = async (req, res) => {

    const { email, password } = req.body;


    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe sont requis' });
    }

    // Préparation de la requête SQL pour récupérer l'utilisateur par son email
    const query = 'SELECT * FROM admin WHERE email = ?';

    // Exécuter la requête SQL
    conn.query(query, [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        // Vérifier si un utilisateur correspondant à l'email
        if (results.length === 0) {
            return res.status(401).json({ error: 'Utilisateur non trouvé' });
        }

        // Extraire le premier utilisateur trouvé (s'il y en a plusieurs)
        const admin = results[0];

        // Comparer le mot de passe fourni avec le mot de passe haché de l'administrateur
        bcrypt.compare(password, admin.password, (bcryptErr, result) => {
            if (bcryptErr) {
                return res.status(500).json({ error: 'Erreur de comparaison de mot de passe' });
            }

            if (!result) {
                return res.status(401).json({ error: 'Mot de passe incorrect' });
            }

            // Signer le token JWT avec l'email autorisé et la clé secrète
            jwt.sign({ payload: { email: emailEnv } }, KEY, { expiresIn: '1h' }, (jwtErr, token) => {
                if (jwtErr) {
                    return res.status(500).json({ error: 'Erreur de génération du token JWT' });
                }
                // Renvoyer le token JWT dans la réponse
                res.status(200).json({ token });
            });
        });
    });
}

const extractBearer = authorization => {
    if (typeof authorization !== 'string') {
        return null;
    }
    const matches = authorization.match(/(bearer)\s+(\S+)/i);

    return matches ? matches[2] : null;
};

const dashboard = (req, res) => {
    const token = req.headers.authorization && extractBearer(req.headers.authorization);

    if (!token) {
        return res.status(401).json({ message: 'Token introuvable' });
    }

    jwt.verify(token, KEY, (err, decodedToken) => {
        if (err) {
            return res.status(401).json({ message: 'Mauvais token' });
        }

        req.decodedToken = decodedToken;

        console.log(decodedToken);

        console.log('Accès autorisé');
        return res.status(200).json({ message: 'Accès autorisé' });
    });
};

// const login = async (req, res) => {

//     const { email, password } = req.body;


//     if (!email || !password) {
//         return res.status(400).json({ error: 'Email et mot de passe sont requis' });
//     }

//     // Préparation de la requête SQL pour récupérer l'utilisateur par son email
//     const query = 'SELECT * FROM admin WHERE email = ?';

//     // Exécuter la requête SQL
//     conn.query(query, [email], (err, results) => {
//         if (err) {
//             return res.status(500).json({ error: err.message });
//         }

//         // Vérifier si un utilisateur correspondant à l'email
//         if (results.length === 0) {
//             return res.status(401).json({ error: 'Utilisateur non trouvé' });
//         }

//         // Extraire le premier utilisateur trouvé (s'il y en a plusieurs)
//         const admin = results[0];

//         // Comparer le mot de passe fourni avec le mot de passe haché de l'administrateur
//         bcrypt.compare(password, admin.password, (bcryptErr, result) => {
//             if (bcryptErr) {
//                 return res.status(500).json({ error: 'Erreur de comparaison de mot de passe' });
//             }

//             if (!result) {
//                 return res.status(401).json({ error: 'Mot de passe incorrect' });
//             }

//             // Si l'authentification réussit, générer le token JWT
//             jwt.sign({ email: emailEnv }, KEY, { expiresIn: '1h' }, (jwtErr, token) => {
//                 if (jwtErr) {
//                     return res.status(500).json({ error: 'Erreur de génération du token JWT' });
//                 }

//                 // Ajouter le token JWT en tant que cookie
//                 res.cookie('token', token, { expires: new Date(Date.now() + 3600000), httpOnly: true });

//                 // Renvoyer une réponse réussie
//                 // res.status(200).json({ message: 'Authentification réussie' });
//                 res.status(200).json({message: 'Authentification réussie, voici votre token :', token });
//             })
//         })
//     });
// }

// const dashboard = (req, res) => {
//     // Extraire le token du cookie nommé "token"
//     const token = req.cookies.token;

//     if (!token) {
//         return res.status(401).json({ message: 'Token introuvable' });
//     }

//     jwt.verify(token, KEY, (err, decodedToken) => {
//         if (err) {
//             return res.status(401).json({ message: 'Mauvais token' });
//         }

//         req.decodedToken = decodedToken;

//         console.log(decodedToken);

//         console.log('Accès autorisé');
//         return res.status(200).json({ message: 'Accès autorisé' });
//     });
// };


//Routes
module.exports = {
    register,
    login,
    dashboard
}