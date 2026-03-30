const jwt = require('jsonwebtoken');
require('dotenv').config();

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Missing token' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

function requireManager(req, res, next) {
    if (!['manager', 'admin'].includes(req.user.role)) return res.status(403).json({ message: 'Forbidden' });
    next();
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
    next();
}

module.exports = { authenticateJWT, requireManager, requireAdmin };