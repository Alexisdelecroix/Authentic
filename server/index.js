// Importation des dépendances dotenv, express, body-parser, cors, et les routes.
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const userRoutes = require('./routes/auth.route')
const cors = require('cors');
const cookieParser = require('cookie-parser')


// Connection à la base de données.
const connectDb = require ('./config/db')

// Middlewares.
const app = express();

// Middleware pour traiter le corps des requêtes HTTP au format JSON
app.use(express.json());

// Middleware bodyParser pour analyser le corps des requêtes HTTP au format JSON
app.use(bodyParser.json());

// Middleware bodyParser pour analyser le corps des requêtes HTTP avec les données de formulaire URL-encoded
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware cors pour gérer les requêtes Cross-Origin Resource Sharing (CORS)
app.use(cors({
    origin: 'http://localhost:5500',
    optionsSuccessStatus: 200
}));

app.use(cookieParser())

// Vérification de mon localHost en affichant le messahe Hello World
// app.get('/', (req,res) => {
//     res.send('Hello World')
// });

app.use('/', userRoutes)

// Configuration et lancement du serveur
const start = async () => {
    try {
        await connectDb();
        const port = process.env.PORT || 5000;
        app.listen(port, () => {
            console.log(`le serveur à démarré sur le port ${port}`);
        })
    } catch (error) {
        console.log(`Erreur lors du démarrage du serveur`);
    }
};

start();