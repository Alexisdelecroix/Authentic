const express = require('express');
const router = express.Router();
const userController = require('../controllers/auth.controller');


router.post('/api/register', userController.register)


router.post('/api/login', userController.login)

router.get('/api/dashboard', userController.dashboard)


module.exports = router;


