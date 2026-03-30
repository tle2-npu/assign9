function requireManager(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.role === 'manager' || req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ error: 'Manager role required' });
    }
}

function requireAdmin(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ error: 'Admin role required' });
    }
}

module.exports = {
    requireManager,
    requireAdmin
};