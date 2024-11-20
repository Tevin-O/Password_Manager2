import express from 'express';
import Keychain from './pm_main.js';

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Mock database
let userDatabase = {}; // { username: { salt, representation } }

// Setup a new user
app.post('/setup', async (req, res) => {
    const { username, password } = req.body;

    if (userDatabase[username]) {
        console.log(`Setup failed: User ${username} already exists.`);
        return res.status(400).json({ message: 'User already exists!' });
    }

    try {
        console.log(`Setting up user: ${username}`);
        
        const keychain = await Keychain.init(password);
        const { repr, checksum } = await keychain.dump();

        userDatabase[username] = { 
            salt: keychain.salt, 
            representation: repr, 
            checksum 
        };

        console.log('User Database after setup:', JSON.stringify(userDatabase, null, 2));
        res.json({ message: 'User setup complete!' });
    } catch (error) {
        console.error(`Error during user setup for ${username}:`, error.message);
        res.status(500).json({ message: 'User setup failed!' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    const user = userDatabase[username];
    if (!user) {
        console.log(`Login failed: User ${username} not found.`);
        return res.status(404).json({ success: false, message: 'User not found!' });
    }

    try {
        console.log(`Attempting login for user: ${username}`);
        console.log(`Password provided: ${password}`);
        console.log(`Representation loaded: ${user.representation}`);
        console.log(`Checksum loaded: ${user.checksum}`);

        // Attempt to load the keychain
        const keychain = await Keychain.load(
            password,
            user.representation,
            JSON.parse(user.representation),
            user.checksum
        );

        if (keychain) {
            console.log(`Login successful for user: ${username}`);
            res.json({ success: true, message: 'Login successful!' });
        } else {
            console.log(`Invalid password for user: ${username}`);
            res.status(401).json({ success: false, message: 'Invalid password!' });
        }
    } catch (error) {
        console.error(`Login failed for ${username}:`, error.message);
        res.status(401).json({ success: false, message: 'Login failed!' });
    }
});

// Start the server
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
