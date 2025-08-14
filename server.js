
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cors());

// Rate Limiting
const { authLimiter } = require('./middleware/rateLimitMiddleware');
app.use('/api/auth', authLimiter);

// Routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Database Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log(err));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
