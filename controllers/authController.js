const authService = require('../services/authService');

const register = async (req, res) => {
    try {
        const { email, password, phone, walletAddress } = req.body;
        const user = await authService.register(email, password, phone, walletAddress);
        res.status(201).json({ message: 'User registered successfully', user });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await authService.login(email, password);
        res.status(200).json(result);
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
};

const getMetamaskNonce = async (req, res) => {
    try {
        const { walletAddress } = req.params;
        const nonce = await authService.getMetamaskNonce(walletAddress);
        res.status(200).json({ nonce });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const verifyMetamaskSignature = async (req, res) => {
    try {
        const { walletAddress, signature } = req.body;
        const result = await authService.verifyMetamaskSignature(walletAddress, signature);
        res.status(200).json(result);
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
};

const verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;
        await authService.verifyEmail(token);
        res.status(200).json({ message: 'Email verified successfully' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const generateTwoFactorSecret = async (req, res) => {
    try {
        const { userId } = req.user;
        const { secret, qrCode } = await authService.generateTwoFactorSecret(userId);
        res.status(200).json({ secret, qrCode });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const verifyTwoFactor = async (req, res) => {
    try {
        const { email, token } = req.body;
        const result = await authService.verifyTwoFactor(email, token);
        res.status(200).json(result);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        await authService.forgotPassword(email);
        res.status(200).json({ message: 'Password reset email sent' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        await authService.resetPassword(token, password);
        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
};

module.exports = {
    register,
    login,
    getMetamaskNonce,
    verifyMetamaskSignature,
    verifyEmail,
    generateTwoFactorSecret,
    verifyTwoFactor,
    forgotPassword,
    resetPassword,
};