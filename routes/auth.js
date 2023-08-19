const express = require('express');
const authRouter = express.Router();
const { signupUserWithEmail,loginWithToken,loginUserWithEmail } = require('../controllers/authController');

authRouter.post('/login/token',loginWithToken)
authRouter.post('/signup/email',signupUserWithEmail)
authRouter.post('/login/email',loginUserWithEmail)



module.exports = authRouter;