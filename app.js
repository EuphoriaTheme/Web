const express = require('express');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const { MongoClient } = require('mongodb');
const DiscordStrategy = require('passport-discord').Strategy;
const flash = require('connect-flash');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

// Load environment variables
require('dotenv').config();

const app = express();
const mongoUrl = process.env.MONGO_URL; // Use the MONGO_URL from .env
const dbName = process.env.MONGO_DB; // Use the MONGO_DB from .env
let db;

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public/views'));

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public'))); // This should be after setting the view engine

// Set up session
app.use(session({
    secret: process.env.SESSION_SECRET || 'default_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());
app.use(flash());

app.use((req, res, next) => {
    res.locals.messages = req.flash('error');
    next();
});

// MongoDB connection
MongoClient.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    db = client.db(dbName);
    console.log('Connected to MongoDB');
  })
  .catch(error => console.error('Failed to connect to MongoDB:', error));

// Middleware for API authentication
async function authenticate(req, res, next) {
    // Check for the Authorization header
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    // Extract the token from the Authorization header
    const token = authHeader.split(' ')[1]; // Assuming the format is "Bearer <token>"
    if (!token) {
        return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    try {
        // Fetch the user based on the provided token
        const user = await db.collection('Subscribers').findOne({ apiKey: token });
        if (!user) {
            return res.status(403).json({ success: false, message: 'Unauthorized access' });
        }

        // Attach the user object to the request
        req.user = user;
        next(); // Proceed to the next middleware or route handler
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

// Configure Passport to use Discord Strategy
passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_REDIRECT_URI,
    scope: ['identify', 'email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const collection = db.collection('Subscribers');
        let user = await collection.findOne({ userID: profile.id });

        console.log("Discord Profile:", profile);
        console.log("Found User:", user);

        if (user && user.rolename === "Customer") {
            return done(null, user);
        } else {
            console.log('No access to the application');
            return done(null, false, { message: 'No access to the application' });
        }
    } catch (err) {
        console.error(err);
        return done(err, null);
    }
}));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.userID);
});

passport.deserializeUser(async (userID, done) => {
    try {
        const collection = db.collection('Subscribers');
        const user = await collection.findOne({ userID: userID });
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(__dirname, 'public', req.user.userID.toString());
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true }); // Create the directory if it doesn't exist
        }
        cb(null, userDir); // Set the destination to the user directory
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname)); // Generate a unique filename
    }
});

const upload = multer({ storage: storage });

// Define routes
app.get('/', (req, res) => {

        // Set Open Graph meta tags for the dashboard
        const openGraphData = {
            title: "Euphoria - Home",
            description: "A Theme built for Pterodactyl, using the Blueprint Framework!",
            image: "https://euphoriatheme.uk/images/Ptero.png",
            url: "https://euphoriatheme.uk",
            type: "website"
        };

    res.render('index', { title: 'Home', user: req.user, message: req.flash('error'), openGraphData });
});

app.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/'); // Redirect to home if not authenticated
    }

        // Set Open Graph meta tags for the dashboard
        const openGraphData = {
            title: "Euphoria - Dashboard",
            description: "Manage API Tokens & Manage your Gallery.",
            image: "https://euphoriatheme.uk/images/Ptero.png",
            url: "https://euphoriatheme.uk/dashboard",
            type: "website"
        };

    res.render('Dashboard', { title: 'Dashboard', user: req.user, openGraphData });
});


app.get('/documentation', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }

        // Set Open Graph meta tags for the documentation
        const openGraphData = {
            title: "Euphoria - Documentation",
            description: "View our API Documentation.",
            image: "https://euphoriatheme.uk/images/Ptero.png",
            url: "https://euphoriatheme.uk/documentation",
            type: "website"
        };

    res.render('Documentation', { title: 'Documentation', user: req.user, openGraphData }); // Pass user information if needed
});

// Endpoint to upload an image
app.post('/api/gallery/upload', upload.single('image'), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Not authenticated' });
    }

    try {
        const imageUrl = `/${req.user.userID}/${req.file.filename}`; // Generate the URL for the uploaded image
        res.json({ success: true, imageUrl: imageUrl });
    } catch (err) {
        console.error('Error uploading image:', err);
        res.status(500).json({ error: 'Failed to upload image' });
    }
});

// API Routes
app.use('/api/call', authenticate);

app.get('/api/call/status', (req, res) => {
    res.json({
        success: true,
        status: 'online',
        version: '1.0.0'
    });
});

// Example API endpoint for retrieving gallery images
app.get('/api/call/gallery', async (req, res) => {
    const userDir = path.join(__dirname, 'public', req.user.userID.toString());

    // Check if the user's directory exists
    if (!fs.existsSync(userDir)) {
        return res.json({ success: true, gallery: [] });
    }

    try {
        const files = fs.readdirSync(userDir);
        const imageUrls = files
            .filter(file => /\.(jpg|jpeg|png|gif)$/.test(file))
            .map(file => `https://euphoriatheme.uk/${req.user.userID}/${file}`); // Prepend base URL

        res.json({ success: true, gallery: imageUrls });
    } catch (err) {
        console.error('Error fetching gallery images:', err);
        res.status(500).json({ success: false, message: 'Error fetching gallery images' });
    }
});

// Get gallery images
app.get('/api/gallery', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'public', req.user.userID.toString());

    if (!fs.existsSync(userDir)) {
        return res.json({ success: true, gallery: [] });
    }

    try {
        const files = fs.readdirSync(userDir);
        const imageUrls = files
            .filter(file => /\.(jpg|jpeg|png|gif)$/.test(file))
            .map(file => `/${req.user.userID}/${file}`); // Corrected image URL

        res.json({ success: true, gallery: imageUrls });
    } catch (err) {
        console.error('Error fetching gallery images:', err);
        res.status(500).json({ error: 'Error fetching gallery images' });
    }
});

// Delete an image
app.delete('/api/gallery/delete', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Not authenticated' });
    }

    const imagePath = req.body.imagePath; // The relative path of the image to delete
    const fullPath = path.join(__dirname, 'public', req.user.userID.toString(), path.basename(imagePath)); // Construct full path using path.basename

    try {
        fs.unlink(fullPath, (err) => {
            if (err) {
                console.error('Error deleting image:', err);
                return res.status(500).json({ error: 'Failed to delete image' });
            }
            res.json({ success: true }); // Successfully deleted
        });
    } catch (err) {
        console.error('Error deleting image:', err);
        res.status(500).json({ error: 'Failed to delete image' });
    }
});

app.post('/api/token/roll', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(403).json({ error: 'Not authenticated' }); // Respond with error if not authenticated
    }

    try {
        const collection = db.collection('Subscribers');
        const newToken = jwt.sign(
            { id: req.user.userID, username: req.user.username }, // Payload for the new JWT
            process.env.JWT_SECRET // Secret key from environment
        );

        // Update the user's record with the new token
        await collection.updateOne(
            { userID: req.user.userID }, // Find the user
            { $set: { apiKey: newToken } } // Update the apiKey with the new JWT
        );

        res.json({ success: true, apiKey: newToken }); // Respond with the new token
    } catch (err) {
        console.error('Error updating token:', err);
        res.status(500).json({ error: 'Failed to update token' });
    }
});

// Auth routes
app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', 
    passport.authenticate('discord', { failureRedirect: '/' }),
    async (req, res) => {
        if (!req.user) {
            req.flash('error', 'No access to the application');
            return res.redirect('/');
        }
        res.redirect('/dashboard');
    }
);

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
            return res.redirect('/');
        }
        res.redirect('/');
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
