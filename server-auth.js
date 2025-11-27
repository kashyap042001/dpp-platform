/**
 * Digital Product Passport Platform - Backend with Authentication
 * Node.js + Express + Authentication + Edit Passports
 */

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// ==================== SETUP ====================

if (!fs.existsSync('public')) fs.mkdirSync('public');
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('data')) fs.mkdirSync('data');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Serve HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dpp-with-auth.html'));
});

// File upload
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
    fileFilter: (req, file, cb) => {
        if (file.mimetype !== 'application/pdf') {
            return cb(new Error('Only PDF files allowed'));
        }
        cb(null, true);
    },
    limits: { fileSize: 10 * 1024 * 1024 }
});

// ==================== DATABASE FILES ====================

const USERS_FILE = 'data/users.json';
const PASSPORTS_FILE = 'data/passports.json';

function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }
    } catch (error) {
        console.error('Error reading users:', error);
    }
    return [];
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadPassports() {
    try {
        if (fs.existsSync(PASSPORTS_FILE)) {
            return JSON.parse(fs.readFileSync(PASSPORTS_FILE, 'utf8'));
        }
    } catch (error) {
        console.error('Error reading passports:', error);
    }
    return [];
}

function savePassports(passports) {
    fs.writeFileSync(PASSPORTS_FILE, JSON.stringify(passports, null, 2));
}

// ==================== AUTHENTICATION HELPERS ====================

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function createToken(userId, email) {
    return Buffer.from(JSON.stringify({ userId, email, timestamp: Date.now() })).toString('base64');
}

function verifyToken(token) {
    try {
        const decoded = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
        return decoded;
    } catch (error) {
        return null;
    }
}

function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
}

// ==================== AUTH ROUTES ====================

app.post('/auth/register', (req, res) => {
    try {
        const { email, password, studentName } = req.body;
        
        if (!email || !password || !studentName) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const users = loadUsers();
        
        if (users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const newUser = {
            id: Date.now().toString(),
            email,
            password: hashPassword(password),
            studentName,
            createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        saveUsers(users);
        
        const token = createToken(newUser.id, email);
        
        res.status(201).json({
            success: true,
            message: 'Account created successfully',
            token,
            user: { id: newUser.id, email, studentName }
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const users = loadUsers();
        const user = users.find(u => u.email === email);
        
        if (!user || user.password !== hashPassword(password)) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        const token = createToken(user.id, email);
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: { id: user.id, email: user.email, studentName: user.studentName }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==================== PASSPORT ROUTES ====================

app.get('/passports', (req, res) => {
    try {
        let passports = loadPassports();
        
        if (req.headers.authorization) {
            const token = req.headers.authorization.replace('Bearer ', '');
            const user = verifyToken(token);
            
            if (user) {
                passports = passports.filter(p => 
                    p.studentId === user.userId || p.isPublic === true
                );
            }
        } else {
            passports = passports.filter(p => p.isPublic === true);
        }
        
        res.json(passports.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt)));
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch passports' });
    }
});

app.get('/passports/my', authMiddleware, (req, res) => {
    try {
        const passports = loadPassports();
        const myPassports = passports.filter(p => p.studentId === req.user.userId);
        res.json(myPassports.sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt)));
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch passports' });
    }
});

app.post('/passports', authMiddleware, upload.fields([
    { name: 'productManual', maxCount: 1 },
    { name: 'serviceManual', maxCount: 1 },
    { name: 'disassemblyGuide', maxCount: 1 },
    { name: 'safetyInstructions', maxCount: 1 },
    { name: 'wasteSortingGuide', maxCount: 1 }
]), (req, res) => {
    try {
        const passports = loadPassports();
        
        if (passports.find(p => p.serialNumber === req.body.serialNumber && p.studentId === req.user.userId)) {
            return res.status(400).json({ error: 'Serial number already used by you' });
        }
        
        const files = {};
        const fileKeys = ['productManual', 'serviceManual', 'disassemblyGuide', 'safetyInstructions', 'wasteSortingGuide'];
        
        fileKeys.forEach(key => {
            if (req.files && req.files[key] && req.files[key][0]) {
                files[key] = `/uploads/${req.files[key][0].filename}`;
            }
        });
        
        const newPassport = {
            id: Date.now().toString(),
            studentId: req.user.userId,
            studentEmail: req.user.email,
            productName: req.body.productName,
            serialNumber: req.body.serialNumber,
            productNumber: req.body.productNumber,
            manufacturingDate: req.body.manufacturingDate,
            countryOfOrigin: req.body.countryOfOrigin,
            averageLifetime: req.body.averageLifetime,
            recycledContent: req.body.recycledContent,
            materialComposition: req.body.materialComposition,
            hazardousSubstances: req.body.hazardousSubstances,
            sparePartsAvailability: req.body.sparePartsAvailability,
            billOfMaterials: req.body.billOfMaterials,
            files,
            environmentalConditions: req.body.environmentalConditions,
            runningHours: req.body.runningHours,
            maintenanceCycles: req.body.maintenanceCycles,
            notes: req.body.notes,
            isPublic: req.body.isPublic === 'true',
            status: 'Submitted',
            submittedAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
        
        passports.push(newPassport);
        savePassports(passports);
        
        res.status(201).json({
            success: true,
            message: 'Passport created successfully',
            passport: newPassport
        });
        
    } catch (error) {
        console.error('Error creating passport:', error);
        res.status(500).json({ error: 'Failed to create passport' });
    }
});

app.put('/passports/:id', authMiddleware, upload.fields([
    { name: 'productManual', maxCount: 1 },
    { name: 'serviceManual', maxCount: 1 },
    { name: 'disassemblyGuide', maxCount: 1 },
    { name: 'safetyInstructions', maxCount: 1 },
    { name: 'wasteSortingGuide', maxCount: 1 }
]), (req, res) => {
    try {
        const passports = loadPassports();
        const index = passports.findIndex(p => p.id === req.params.id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Passport not found' });
        }
        
        const passport = passports[index];
        
        if (passport.studentId !== req.user.userId) {
            return res.status(403).json({ error: 'You can only edit your own passports' });
        }
        
        if (req.body.productName) passport.productName = req.body.productName;
        if (req.body.productNumber) passport.productNumber = req.body.productNumber;
        if (req.body.averageLifetime) passport.averageLifetime = req.body.averageLifetime;
        if (req.body.recycledContent) passport.recycledContent = req.body.recycledContent;
        if (req.body.materialComposition) passport.materialComposition = req.body.materialComposition;
        if (req.body.hazardousSubstances) passport.hazardousSubstances = req.body.hazardousSubstances;
        if (req.body.sparePartsAvailability) passport.sparePartsAvailability = req.body.sparePartsAvailability;
        if (req.body.billOfMaterials) passport.billOfMaterials = req.body.billOfMaterials;
        if (req.body.notes) passport.notes = req.body.notes;
        if (req.body.isPublic !== undefined) passport.isPublic = req.body.isPublic === 'true';
        
        const fileKeys = ['productManual', 'serviceManual', 'disassemblyGuide', 'safetyInstructions', 'wasteSortingGuide'];
        fileKeys.forEach(key => {
            if (req.files && req.files[key] && req.files[key][0]) {
                passport.files[key] = `/uploads/${req.files[key][0].filename}`;
            }
        });
        
        passport.updatedAt = new Date().toISOString();
        
        passports[index] = passport;
        savePassports(passports);
        
        res.json({
            success: true,
            message: 'Passport updated successfully',
            passport
        });
        
    } catch (error) {
        console.error('Error updating passport:', error);
        res.status(500).json({ error: 'Failed to update passport' });
    }
});

app.delete('/passports/:id', authMiddleware, (req, res) => {
    try {
        const passports = loadPassports();
        const index = passports.findIndex(p => p.id === req.params.id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Passport not found' });
        }
        
        const passport = passports[index];
        
        if (passport.studentId !== req.user.userId) {
            return res.status(403).json({ error: 'You can only delete your own passports' });
        }
        
        Object.values(passport.files || {}).forEach(filePath => {
            const fullPath = path.join(__dirname, filePath);
            if (fs.existsSync(fullPath)) {
                fs.unlinkSync(fullPath);
            }
        });
        
        passports.splice(index, 1);
        savePassports(passports);
        
        res.json({
            success: true,
            message: 'Passport deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting passport:', error);
        res.status(500).json({ error: 'Failed to delete passport' });
    }
});

app.get('/passports/:id', (req, res) => {
    try {
        const passports = loadPassports();
        const passport = passports.find(p => p.id === req.params.id);
        
        if (!passport) {
            return res.status(404).json({ error: 'Passport not found' });
        }
        
        if (!passport.isPublic) {
            if (req.headers.authorization) {
                const token = req.headers.authorization.replace('Bearer ', '');
                const user = verifyToken(token);
                if (!user || user.userId !== passport.studentId) {
                    return res.status(403).json({ error: 'Access denied' });
                }
            } else {
                return res.status(403).json({ error: 'This passport is private' });
            }
        }
        
        res.json(passport);
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch passport' });
    }
});

app.get('/stats', (req, res) => {
    try {
        const passports = loadPassports();
        const users = loadUsers();
        
        const publicPassports = passports.filter(p => p.isPublic).length;
        const uniquePublicStudents = new Set(passports.filter(p => p.isPublic).map(p => p.studentId)).size;
        
        res.json({
            totalUsers: users.length,
            totalPassports: passports.length,
            publicPassports: publicPassports,
            uniquePublicStudents: uniquePublicStudents
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Server error',
        message: err.message
    });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════════════════╗
    ║   Digital Product Passport Platform             ║
    ║   🚀 With Student Accounts & Edit Features      ║
    ║   Server: http://localhost:${PORT}               ║
    ║   Database: JSON files in /data folder          ║
    ║   Files: Saved in /uploads folder               ║
    ╚══════════════════════════════════════════════════╝
    `);
});

module.exports = app;