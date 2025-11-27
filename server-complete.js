const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// MIDDLEWARE
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MULTER SETUP FOR FILE UPLOADS
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50 MB
});

// MONGODB CONNECTION
const MONGODB_URI =
    process.env.MONGODB_URI ||
    'mongodb+srv://your-username:your-password@cluster0.mongodb.net/dpp?retryWrites=true&w=majority';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';
const PORT = process.env.PORT || 3000;

mongoose
    .connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ MongoDB Error:', err));

// SCHEMAS
const studentSchema = new mongoose.Schema({
    studentName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const passportSchema = new mongoose.Schema({
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true },
    studentEmail: String,
    productName: { type: String, required: true },
    serialNumber: { type: String, required: true },
    productNumber: { type: String, required: true },
    manufacturingDate: { type: Date, required: true },
    countryOfOrigin: { type: String, required: true },
    averageLifetime: { type: Number, required: true },
    recycledContent: { type: Number, required: true },
    materialComposition: { type: String, required: true },
    sparePartsAvailability: { type: String, required: true },
    isPublic: { type: Boolean, default: true },
    status: { type: String, default: 'Active' },
    uploadedFiles: [
        {
            filename: String,
            originalName: String,
            fileSize: Number,
            uploadedAt: { type: Date, default: Date.now }
        }
    ],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Student = mongoose.model('Student', studentSchema);
const Passport = mongoose.model('Passport', passportSchema);

// AUTH ROUTES

// REGISTER
app.post('/auth/register', async (req, res) => {
    try {
        const { studentName, email, password } = req.body;

        if (!studentName || !email || !password) {
            return res.status(400).json({ error: 'All fields required' });
        }

        if (password.length < 6) {
            return res
                .status(400)
                .json({ error: 'Password must be at least 6 characters' });
        }

        const existingStudent = await Student.findOne({ email });
        if (existingStudent) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const student = new Student({
            studentName,
            email,
            password: hashedPassword
        });

        await student.save();

        const token = jwt.sign(
            { id: student._id, email: student.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'Account created successfully',
            token,
            user: {
                id: student._id,
                studentName: student.studentName,
                email: student.email
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// LOGIN
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const student = await Student.findOne({ email });
        if (!student) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isPasswordValid = await bcrypt.compare(password, student.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: student._id, email: student.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: student._id,
                studentName: student.studentName,
                email: student.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// AUTH MIDDLEWARE
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.replace('Bearer ', '');

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        req.userEmail = decoded.email;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// PASSPORT ROUTES

// CREATE PASSPORT
app.post(
    '/passports',
    verifyToken,
    upload.array('files'),
    async (req, res) => {
        try {
            const {
                productName,
                serialNumber,
                productNumber,
                manufacturingDate,
                countryOfOrigin,
                averageLifetime,
                recycledContent,
                materialComposition,
                sparePartsAvailability,
                isPublic
            } = req.body;

            if (!productName || !serialNumber || !productNumber) {
                return res.status(400).json({ error: 'Required fields missing' });
            }

            const uploadedFiles = req.files
                ? req.files.map(file => ({
                      filename: file.filename,
                      originalName: file.originalname,
                      fileSize: file.size,
                      uploadedAt: new Date()
                  }))
                : [];

            const passport = new Passport({
                studentId: req.userId,
                studentEmail: req.userEmail,
                productName,
                serialNumber,
                productNumber,
                manufacturingDate: new Date(manufacturingDate),
                countryOfOrigin,
                averageLifetime: parseInt(averageLifetime),
                recycledContent: parseInt(recycledContent),
                materialComposition,
                sparePartsAvailability,
                isPublic: isPublic === 'true' || isPublic === true,
                uploadedFiles,
                status: 'Active'
            });

            await passport.save();

            res.status(201).json({
                message: 'Passport created successfully',
                passport
            });
        } catch (error) {
            console.error('Create passport error:', error);
            res.status(500).json({ error: 'Server error: ' + error.message });
        }
    }
);

// GET ALL PUBLIC PASSPORTS
app.get('/passports', async (req, res) => {
    try {
        const passports = await Passport.find({ isPublic: true })
            .sort({ createdAt: -1 })
            .limit(50);

        res.json(passports);
    } catch (error) {
        console.error('Get passports error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// GET MY PASSPORTS
app.get('/passports/my', verifyToken, async (req, res) => {
    try {
        const passports = await Passport.find({ studentId: req.userId }).sort({
            createdAt: -1
        });

        res.json(passports);
    } catch (error) {
        console.error('Get my passports error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// GET SINGLE PASSPORT
app.get('/passports/:id', async (req, res) => {
    try {
        const passport = await Passport.findById(req.params.id);

        if (!passport) {
            return res.status(404).json({ error: 'Passport not found' });
        }

        res.json(passport);
    } catch (error) {
        console.error('Get passport error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// UPDATE PASSPORT
app.put(
    '/passports/:id',
    verifyToken,
    upload.array('files'),
    async (req, res) => {
        try {
            const passport = await Passport.findById(req.params.id);

            if (!passport) {
                return res.status(404).json({ error: 'Passport not found' });
            }

            if (passport.studentId.toString() !== req.userId) {
                return res.status(403).json({ error: 'Unauthorized' });
            }

            if (req.body.productName) passport.productName = req.body.productName;
            if (req.body.serialNumber) passport.serialNumber = req.body.serialNumber;
            if (req.body.productNumber) passport.productNumber = req.body.productNumber;
            if (req.body.averageLifetime)
                passport.averageLifetime = parseInt(req.body.averageLifetime);
            if (req.body.recycledContent)
                passport.recycledContent = parseInt(req.body.recycledContent);
            if (req.body.materialComposition)
                passport.materialComposition = req.body.materialComposition;
            if (req.body.sparePartsAvailability)
                passport.sparePartsAvailability = req.body.sparePartsAvailability;
            if (req.body.isPublic !== undefined)
                passport.isPublic =
                    req.body.isPublic === 'true' || req.body.isPublic === true;

            if (req.files && req.files.length > 0) {
                const newFiles = req.files.map(file => ({
                    filename: file.filename,
                    originalName: file.originalname,
                    fileSize: file.size,
                    uploadedAt: new Date()
                }));
                passport.uploadedFiles = [...passport.uploadedFiles, ...newFiles];
            }

            passport.updatedAt = new Date();
            await passport.save();

            res.json({
                message: 'Passport updated successfully',
                passport
            });
        } catch (error) {
            console.error('Update passport error:', error);
            res.status(500).json({ error: 'Server error: ' + error.message });
        }
    }
);

// DELETE PASSPORT
app.delete('/passports/:id', verifyToken, async (req, res) => {
    try {
        const passport = await Passport.findById(req.params.id);

        if (!passport) {
            return res.status(404).json({ error: 'Passport not found' });
        }

        if (passport.studentId.toString() !== req.userId) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        await Passport.findByIdAndDelete(req.params.id);

        res.json({ message: 'Passport deleted successfully' });
    } catch (error) {
        console.error('Delete passport error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// DOWNLOAD FILE
app.get('/files/:filename', (req, res) => {
    try {
        const filename = req.params.filename;
        const filepath = path.join(__dirname, 'uploads', filename);
        res.download(filepath);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// HEALTH CHECK
app.get('/health', (req, res) => {
    res.json({ status: 'Server is running ✅' });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════╗
    ║   DPP BACKEND SERVER RUNNING ✅    ║
    ║   Port: ${PORT}                         ║
    ║   URL: http://localhost:${PORT}        ║
    ╚════════════════════════════════════╝
    `);
});

module.exports = app;
