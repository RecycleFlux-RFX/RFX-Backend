
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true,
    },
    password: {
        type: String,
    },
    isEmailVerified: {
        type: Boolean,
        default: false,
    },
    twoFactorSecret: {
        type: String,
    },
    isTwoFactorEnabled: {
        type: Boolean,
        default: false,
    },
    metamaskNonce: {
        type: String,
    },
    walletAddress: {
        type: String,
        unique: true,
    }
}, { timestamps: true });

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

userSchema.methods.comparePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

module.exports = User;
