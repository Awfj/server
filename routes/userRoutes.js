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
} from "../controllers/user.controller.js";
import { verifyToken } from "../middleware/verifyUser.js";

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

export default userRouter;
