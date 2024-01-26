const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const socketio = require('socket.io');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Initialize Express app
const app = express();
const server = require('http').createServer(app);
const io = socketio(server);

// Connect to MongoDB
mongoose.connect('mongodb+srv://zeenat:abrar@cluster0.rqsbzxg.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;

// Define Schemas
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 50 },
  avatar: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});

const BugSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  source: { type: String, required: true },
  severity: {
    type: String,
    enum: ['Critical', 'Major', 'Medium', 'Low'],
    required: true,
  },
  raised_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

// Define Models
const UserModel = mongoose.model('User', UserSchema);
const BugModel = mongoose.model('Bug', BugSchema);

// Middleware
app.use(express.json());

// Routes

// // Google OAuth

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // Here you can handle user authentication logic
    return cb(null, profile);
  }
));

// Google OAuth route
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth callback route
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });

// Serialize and deserialize user (for session management)
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});


// Register User
app.post(
    '/api/register',
    [
      body('email').isEmail(),
      body('password').isLength({ min: 6 }),
      body('name').isLength({ min: 1, max: 50 }),
    ],
    async (req, res) => {
      // Validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      try {
        const { name, email, password, avatar } = req.body;
  
        // Check if the user already exists
        let user = await UserModel.findOne({ email });
        if (user) {
          return res.status(400).json({ msg: 'User already exists' });
        }
  
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
  
        // Create new user
        user = new UserModel({
          name,
          email,
          password: hashedPassword,
          avatar,
        });
  
        await user.save();
  
        res.status(201).json({ msg: 'User registered successfully' });
      } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
      }
    }
  );
  


// Login User
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      let user = await UserModel.findOne({ email });
  
      if (!user) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
  
      if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
      }
  
      const payload = {
        user: {
          id: user.id,
        },
      };
  
      jwt.sign(
        payload,
        'jwtSecret',
        { expiresIn: 3600 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  


// Get all bugs
app.get('/api/bugs', async (req, res) => {
    try {
      const bugs = await BugModel.find().populate('raised_by', 'name');
      res.json(bugs);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  


// Get bug by ID
app.get('/api/bugs/:id', async (req, res) => {
    try {
      const bug = await BugModel.findById(req.params.id).populate(
        'raised_by',
        'name'
      );
  
      if (!bug) {
        return res.status(404).json({ msg: 'Bug not found' });
      }
  
      res.json(bug);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  
// Authorization middleware for protected routes
const authorize = (req, res, next) => {
    // Get token from header
    const token = req.header('x-auth-token');
  
    // Check if not token
    if (!token) {
      return res.status(401).json({ msg: 'No token, authorization denied' });
    }
  
    // Verify token
    try {
      const decoded = jwt.verify(token, 'jwtSecret');
  
      req.user = decoded.user;
      next();
    } catch (err) {
      res.status(401).json({ msg: 'Token is not valid' });
    }
  };
  

// Add new bug
app.post('/api/bugs', authorize, async (req, res) => {
    try {
      const { title, description, source, severity } = req.body;
  
      const newBug = new BugModel({
        title,
        description,
        source,
        severity,
        raised_by: req.user.id,
      });
  
      const bug = await newBug.save();
  
      res.json(bug);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  

// Update bug by ID
// app.put('/api/bugs/:id', async (req, res) => {
//   // Implementation to update bug by ID
// });
// Update bug by ID
app.put('/api/bugs/:id', authorize, async (req, res) => {
    const { title, description, source, severity } = req.body;
  
    // Build bug object
    const bugFields = {};
    if (title) bugFields.title = title;
    if (description) bugFields.description = description;
    if (source) bugFields.source = source;
    if (severity) bugFields.severity = severity;
  
    try {
      let bug = await BugModel.findById(req.params.id);
  
      if (!bug) {
        return res.status(404).json({ msg: 'Bug not found' });
      }
  
      // Ensure user owns bug
      if (bug.raised_by.toString() !== req.user.id) {
        return res.status(401).json({ msg: 'Not authorized' });
      }
  
      bug = await BugModel.findByIdAndUpdate(
        req.params.id,
        { $set: bugFields },
        { new: true }
      );
  
      res.json(bug);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  


// Delete bug by ID
app.delete('/api/bugs/:id', authorize, async (req, res) => {
    try {
      let bug = await BugModel.findById(req.params.id);
  
      if (!bug) {
        return res.status(404).json({ msg: 'Bug not found' });
      }
  
      // Ensure user owns bug
      if (bug.raised_by.toString() !== req.user.id) {
        return res.status(401).json({ msg: 'Not authorized' });
      }
  
      await BugModel.findByIdAndRemove(req.params.id);
  
      res.json({ msg: 'Bug removed' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  });
  

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});



// Websockets
io.on('connection', (socket) => {
    console.log('User connected');
  
    // Listen for chat messages
    socket.on('chatMessage', (message) => {
      io.emit('message', message); // Broadcast the message to all connected clients
    });
  
    // Handle disconnection
    socket.on('disconnect', () => {
      console.log('User disconnected');
    });
  });
  

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server started on port ${PORT}`));
