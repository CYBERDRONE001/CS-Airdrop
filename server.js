const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 5000;
const secretKey = 'secret123';

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/social_network', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    followers: [String],
    following: [String],
    notifications: [String]
});

const PostSchema = new mongoose.Schema({
    content: String,
    author: String,
    likes: [String],
    comments: [{ user: String, text: String }]
});

const User = mongoose.model('User', UserSchema);
const Post = mongoose.model('Post', PostSchema);

// Nodemailer configuration (use your email credentials)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL, 
        pass: process.env.PASSWORD 
    }
});

// Register new user
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    
    // Notify all users of new signup
    const users = await User.find();
    users.forEach(async user => {
        user.notifications.push(`${username} has joined the network!`);
        await user.save();
    });

    res.send('User registered successfully');
});

// Login user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign({ userId: user._id, username: user.username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
});

// Forgot password
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const resetToken = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '15m' });

    // Send email with reset link
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Password Reset',
        text: `Click here to reset your password: http://localhost:${PORT}/reset-password?token=${resetToken}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) return res.status(500).send('Error sending email');
        res.send('Password reset email sent');
    });
});

// Posting a message
app.post('/post', async (req, res) => {
    const { content, author } = req.body;
    const newPost = new Post({ content, author, likes: [], comments: [] });
    await newPost.save();
    
    // Notify all users of the new post
    const users = await User.find();
    users.forEach(async user => {
        user.notifications.push(`${author} posted a new message!`);
        await user.save();
    });

    res.send('Post created');
});

// Friend request
app.post('/friend-request', async (req, res) => {
    const { fromUserId, toUserId } = req.body;
    const toUser = await User.findById(toUserId);
    if (!toUser) return res.status(400).json({ message: 'User not found' });

    toUser.notifications.push(`${fromUserId} sent you a friend request!`);
    await toUser.save();
    res.send('Friend request sent');
});

// Middleware to protect routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');

    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
}

// Protected route (Example: Get user profile)
app.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.userId);
    res.json({ username: user.username, email: user.email });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
