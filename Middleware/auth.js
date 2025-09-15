const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Akses ditolak, tidak ada token.' });
  }

  try {
    const token = authHeader.split(' ')[1];
    
    const decoded = jwt.verify(token, "your_super_secret_jwt_key");
    
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token tidak valid.' });
  }
};

module.exports = authMiddleware;