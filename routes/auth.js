
const express = require('express');
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/metamask/nonce/:walletAddress', authController.getMetamaskNonce);
router.post('/metamask/verify', authController.verifyMetamaskSignature);
router.get('/verify-email/:token', authController.verifyEmail);
router.post('/2fa/generate', authMiddleware.protect, authController.generateTwoFactorSecret);
router.post('/2fa/verify', authController.verifyTwoFactor);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password/:token', authController.resetPassword);

module.exports = router;
