import express from "express";
import {
  changePassword,
  getProfile,
  googleLogin,
  login,
  register,
  searchUsers,
  updateProfile,
  updateProfileImg,
  followUser,
  unfollowUser,
  isFollowingUser,
  getFollowers,
  getFollowing,
  getFollowersCount,
  getFollowingCount,
  getUsers,
  getUsersCount,
  changeUserRole,
  deleteUser,
} from "../controllers/user.controller.js";
import { verifyToken, checkRole } from "../middleware/verifyUser.js";

const userRouter = express.Router();

userRouter.post("/signup", register);
userRouter.post("/signin", login);
userRouter.post("/google-auth", googleLogin);
userRouter.post("/search-users", searchUsers);
userRouter.post("/get-profile", getProfile);
userRouter.post("/change-password", verifyToken, changePassword);
userRouter.post("/update-profile-img", verifyToken, updateProfileImg);
userRouter.post("/update-profile", verifyToken, updateProfile);
userRouter.post("/follow-user", verifyToken, followUser);
userRouter.post("/unfollow-user", verifyToken, unfollowUser);
userRouter.post("/is-following-user", verifyToken, isFollowingUser);

userRouter.post("/get-followers", getFollowers);
userRouter.post("/get-following", getFollowing);
userRouter.post("/followers-count", getFollowersCount);
userRouter.post("/following-count", getFollowingCount);

userRouter.post("/get-users", verifyToken, getUsers);
userRouter.post("/users-count", verifyToken, getUsersCount);

// userRouter.post("/create-moderator", verifyToken, checkRole('admin'), register);
userRouter.post("/change-user-role", verifyToken, checkRole('admin'), changeUserRole);
userRouter.post("/delete-user", verifyToken, checkRole('admin'), deleteUser);

// userRouter.post("/ban-user", verifyToken, checkRole('admin', 'moderator'), banUser);
// userRouter.post("/unban-user", verifyToken, checkRole('admin', 'moderator'), unbanUser);

export default userRouter;
