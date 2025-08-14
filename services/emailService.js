
const nodemailer = require('nodemailer');

const sendVerificationEmail = async (to, token) => {
    if (process.env.NODE_ENV === 'development') {
        console.log(`Verification email sent to ${to} with token ${token}`);
        return;
    }

    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to,
        subject: 'Email Verification',
        text: `Please verify your email by clicking the following link: http://localhost:3000/api/auth/verify-email/${token}`,
    };

    await transporter.sendMail(mailOptions);
};

const sendPasswordResetEmail = async (to, token) => {
    if (process.env.NODE_ENV === 'development') {
        console.log(`Password reset email sent to ${to} with token ${token}`);
        return;
    }

    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        secure: false,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to,
        subject: 'Password Reset',
        text: `Please reset your password by clicking the following link: http://localhost:3000/api/auth/reset-password/${token}`,
    };

    await transporter.sendMail(mailOptions);
};

module.exports = {
    sendVerificationEmail,
    sendPasswordResetEmail,
};
