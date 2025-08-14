
const User = require('../models/User');
const Token = require('../models/Token');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const emailService = require('./emailService');
const { ethers } = require('ethers');

const register = async (email, password, phone, walletAddress) => {
    const user = new User({ email, password, phone, walletAddress });
    await user.save();

    if (process.env.ENABLE_EMAIL_VERIFICATION === 'true' && email) {
        const token = crypto.randomBytes(20).toString('hex');
        const verificationToken = new Token({ userId: user._id, token });
        await verificationToken.save();
        await emailService.sendVerificationEmail(user.email, verificationToken.token);
    }

    return user;
};

const login = async (email, password) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw new Error('Invalid credentials');
    }

    if (user.walletAddress) {
        throw new Error('Please login with Metamask');
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
        throw new Error('Invalid credentials');
    }

    if (user.isTwoFactorEnabled) {
        return { twoFactorEnabled: true };
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });

    return { token };
};

const getMetamaskNonce = async (walletAddress) => {
    const nonce = crypto.randomBytes(32).toString('hex');
    let user = await User.findOne({ walletAddress });
    if (!user) {
        user = new User({ walletAddress });
    }
    user.metamaskNonce = nonce;
    await user.save();
    return nonce;
};

const verifyMetamaskSignature = async (walletAddress, signature) => {
    const user = await User.findOne({ walletAddress });
    if (!user) {
        throw new Error('User not found');
    }

    const message = `Please sign this message to login: ${user.metamaskNonce}`;
    const recoveredAddress = ethers.utils.verifyMessage(message, signature);

    if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
        throw new Error('Invalid signature');
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });

    user.metamaskNonce = null;
    await user.save();

    return { token };
};

const verifyEmail = async (token) => {
    const verificationToken = await Token.findOne({ token });
    if (!verificationToken) {
        throw new Error('Invalid token');
    }

    const user = await User.findById(verificationToken.userId);
    if (!user) {
        throw new Error('User not found');
    }

    user.isEmailVerified = true;
    await user.save();
    await verificationToken.remove();
};

const generateTwoFactorSecret = async (userId) => {
    const secret = speakeasy.generateSecret({ length: 20 });
    await User.findByIdAndUpdate(userId, { twoFactorSecret: secret.base32, isTwoFactorEnabled: true });
    const qrCode = await qrcode.toDataURL(secret.otpauth_url);
    return { secret: secret.base32, qrCode };
};

const verifyTwoFactor = async (userId, token) => {
    const user = await User.findById(userId);
    const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token,
    });

    if (verified) {
        const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
        });
        return { token: jwtToken };
    }

    return { token: null };
};

const forgotPassword = async (email) => {
    const user = await User.findOne({ email });
    if (!user) {
        throw new Error('User not found');
    }

    const token = crypto.randomBytes(20).toString('hex');
    const resetToken = new Token({ userId: user._id, token });
    await resetToken.save();

    await emailService.sendPasswordResetEmail(user.email, resetToken.token);
};

const resetPassword = async (token, password) => {
    const resetToken = await Token.findOne({ token });
    if (!resetToken) {
        throw new Error('Invalid token');
    }

    const user = await User.findById(resetToken.userId);
    if (!user) {
        throw new Error('User not found');
    }

    user.password = password;
    await user.save();
    await resetToken.remove();
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
