import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  // console.log(token)
  if (!token) {
    return res.status(401).json({ error: "No access token" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is Invalid" });
    }
    req.user = user.id;
    next();
  });
};

export const checkRole = (...roles) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user).select("role");

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (!roles.includes(user.role)) {
        return res.status(403).json({
          error: "You don't have permission to perform this action",
        });
      }

      next();
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  };
};
