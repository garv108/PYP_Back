const bcrypt = require('bcryptjs');
const User = require('../models/user'); 

// Signup handler
exports.signup = async (req, res) => {
    const { fullname, email, password } = req.body;

    try {
        // Check if the user already exists
        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(400).json({ message: "User already exists!" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({
            fullname,
            email,
            password: hashedPassword
        });

        // Save the user to the database
        await newUser.save();

        res.status(201).json({ message: "User created successfully!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error!" });
    }
    
// Login handler
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid credentials!" });
        }

        // 2. Compare hashed password with input password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials!" });
        }

        // 3. (Optional) Generate & send a JWT token for authentication
        //const token = generateToken(user._id); 
        //res.status(200).json({ token, message: "Login successful!" });

        // 4. If no token, just confirm login
        res.status(200).json({ message: "Login successful!" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error!" });
    }

    }
};
// Logout handler
exports.logout = (req, res) => {
    // Clear the token from the client side (handled in frontend)
    res.status(200).json({ message: "Logout successful!" });
};
