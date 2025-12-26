const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports =async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ msg: "Token is missing" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ msg: "Invalid token format" });
    }
    

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decoded);
    
    const isBlock = await User.findById(decoded.id).select('isBlock -_id')
    console.log(isBlock)
    if (!isBlock.isBlock) {
      req.userId = decoded.id; 
      next();
    } else {
      return res.status(403).json({ msg: "Authorization denied" });
    }
  } catch (error) {
    console.error(error);
    return res.status(401).json({ msg: "Invalid or expired token" });
  }
};
