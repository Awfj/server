import { getAuth } from "firebase-admin/auth";
import User from "../Schema/User.js";
import ErrorHanlder from "../utils/Errorhandler.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import Blog from "../Schema/Blog.js";

const generateUserName = async (email) => {
  let username = email.split("@")[0];
  let isUserNameUnique = await User.exists({
    "personal_info.username": username,
  }).then((result) => result);

  isUserNameUnique ? (username += nanoid().substring(0, 5)) : "";

  return username;
};
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

const formatDataToSend = (user) => {
  const access_token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
    role: user.role,
  };
};
export const register = async (req, res, next) => {
  try {
    const { fullname, email, password } = req.body;
    if (!fullname || fullname.length < 3)
      return next(new ErrorHanlder(403, "Full name must be 3 letters long"));
    if (!email.length) return res.status(403).json({ error: "Enter email" });

    if (!emailRegex.test(email)) {
      return res.status(403).json({ error: "Email is invalid" });
    }
    if (!passwordRegex.test(password)) {
      return res.status(403).json({
        error:
          "password should be 6 to 20 characters long with a numeric, 1 uppercase and 1 lowercase lettes",
      });
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {
      let username = await generateUserName(email);
      let user = new User({
        personal_info: {
          fullname,
          email,
          password: hashed_password,
          username,
        },
      });
      user
        .save()
        .then((u) => {
          return res.status(200).json(formatDataToSend(u));
        })
        .catch((err) => {
          if (err.code === 11000) {
            return res.status(500).json({ error: "Email already exists" });
          }
          return res.status(500).json({ error: err.message });
        });
    });
    // return res.status(200).json({'status': "ok"})
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const login = async (req, res) => {
  try {
    let { email, password } = req.body;
    User.findOne({ "personal_info.email": email })
      .then((user) => {
        if (!user) {
          return res.status(403).json({ error: "Email not found" });
        }
        if (!user.google_auth) {
          bcrypt.compare(
            password,
            user.personal_info.password,
            (err, result) => {
              if (err)
                return res
                  .status(403)
                  .json({ error: "Error Occur while login please try again" });

              if (!result) {
                return res.status(403).json({ error: "Invalid Credential" });
              } else {
                return res.status(200).json(formatDataToSend(user));
              }
            }
          );
        } else {
          return res.status(403).json({
            error: "Account was created using google. Try using Google",
          });
        }
      })
      .catch((err) => {
        console.log(err);
        return res.status(500).json({ error: err.message });
      });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const googleLogin = async (req, res) => {
  try {
    let { access_token } = req.body;
    // console.log(access_token)

    getAuth()
      .verifyIdToken(access_token)
      .then(async (decodedUser) => {
        let { email, name, picture } = decodedUser;
        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ "personal_info.email": email })
          .select(
            "personal_info.fullname personal_info.fullname personal_info.username personal_info.profile_img google_auth"
          )
          .then((u) => {
            return u || null;
          })
          .catch((err) => {
            return res.status(505).json({ error: err.message });
          });

        if (user) {
          // login
          if (!user.google_auth) {
            return res.status(403).json({
              error:
                "This email was signed up without google. Please log in with password to access the account",
            });
          }
        } else {
          // sign up
          let username = await generateUserName(email);
          user = new User({
            personal_info: {
              fullname: name,
              email,
              profile_img: picture,
              username,
            },
            google_auth: true,
          });
          await user
            .save()
            .then((u) => {
              user = u;
            })
            .catch((err) => {
              return res.status(505).json({ error: err.message });
            });
        }

        return res.status(200).json(formatDataToSend(user));
      })
      .catch((err) => {
        return res.status(500).json({
          error:
            "Failed to authenticate you with goole, Try with others account",
        });
      });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const searchUsers = (req, res) => {
  try {
    let { query } = req.body;
    User.find({ "personal_info.username": new RegExp(query, "i") })
      .limit(50)
      .select(
        "personal_info.fullname personal_info.username personal_info.profile_img -_id"
      )
      .then((users) => {
        return res.status(200).json({ users });
      })
      .catch((err) => {
        return res.status(500).json({ error: err.message });
      });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

export const getProfile = (req, res) => {
  try {
    let { username } = req.body;
    User.findOne({ "personal_info.username": username })
      .select("-personal_info.password -google_auth -updatedAt -blogs")
      .then((user) => {
        return res.status(200).json(user);
      })
      .catch((err) => {
        console.log(err);
        return res.status(500).json({ error: err.message });
      });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

export const changePassword = (req, res) => {
  let { currentPassword, newPassword } = req.body;

  if (
    !passwordRegex.test(currentPassword) ||
    !passwordRegex.test(newPassword)
  ) {
    return res.status(403).json({
      error:
        "password should be 6 to 20 characters long with a numeric, 1 uppercase and 1 lowercase lettes",
    });
  }

  User.findOne({ _id: req.user })
    .then((user) => {
      if (user.google_auth) {
        return res.status(403).json({
          error:
            "You cannot change account's password because you logged in through google",
        });
      }

      bcrypt.compare(
        currentPassword,
        user.personal_info.password,
        (err, result) => {
          if (err) {
            return res.status(500).json({
              error:
                "Some error occured while changing the password, please try again later",
            });
          }

          if (!result) {
            return res
              .status(403)
              .json({ error: "Incorrect current Password" });
          }

          bcrypt.hash(newPassword, 10, (err, hashed_password) => {
            if (err) {
              return res.status(500).json({ error: err.message });
            }
            User.findOneAndUpdate(
              { _id: req.user },
              { "personal_info.password": hashed_password }
            )
              .then((u) => {
                return res.status(200).json({ status: "password changed" });
              })
              .catch((err) => {
                return res.status(500).json({
                  error:
                    "Some error occured while saving the new password, please try again later",
                });
              });
          });
        }
      );
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ error: "User not found" });
    });
};

export const updateProfileImg = (req, res) => {
  let { url } = req.body;

  User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
    .then(() => {
      return res.status(200).json({ profile_img: url });
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
};

export const updateProfile = (req, res) => {
  let { username, bio, social_links } = req.body;

  let bioLimit = 150;
  if (username.length < 3) {
    return res
      .status(403)
      .json({ error: "Username should be at least 3 letter long" });
  }

  if (bio.length > bioLimit) {
    return res
      .status(403)
      .json({ error: `Bio should not be more than ${bioLimit} characters` });
  }

  let socialLinksArr = Object.keys(social_links);
  try {
    for (let i = 0; i < socialLinksArr.length; i++) {
      if (social_links[socialLinksArr[i]].length) {
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if (
          !hostname.includes(`${socialLinksArr[i]}.com`) &&
          socialLinksArr[i] != "website"
        ) {
          return res.status(403).json({
            error: `${socialLinksArr[i]} link is invalid. You must enter a valid link.`,
          });
        }
      }
    }
  } catch (error) {
    return res.status(500).json({
      error: "You must provide full social links with http(s) include",
    });
  }

  let updateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links,
  };

  User.findOneAndUpdate({ _id: req.user }, updateObj, {
    runValidators: true,
  })
    .then(() => {
      return res.status(200).json({ username });
    })
    .catch((err) => {
      if (err.code == 11000) {
        return res.status(409).json({ error: "Username is already taken" });
      }
      return res.status(500).json({ error: err.message });
    });
};

// FOLLOWING AND UNFOLLOWING USERS
export const followUser = async (req, res) => {
  try {
    const userId = req.user;
    const { targetUserId } = req.body;

    // Check if users exist
    const [user, targetUser] = await Promise.all([
      User.findById(userId),
      User.findById(targetUserId),
    ]);

    if (!user || !targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Prevent self-following
    if (userId === targetUserId) {
      return res.status(400).json({ error: "You cannot follow yourself" });
    }

    // Check if already following
    if (user.following.includes(targetUserId)) {
      return res.status(400).json({ error: "Already following this user" });
    }

    // Add relationships using transaction
    const session = await User.startSession();
    try {
      await session.withTransaction(async () => {
        // Update following user
        await User.findByIdAndUpdate(
          userId,
          {
            $addToSet: { following: targetUserId },
            $inc: { "account_info.total_following": 1 },
          },
          { session }
        );

        // Update followed user
        await User.findByIdAndUpdate(
          targetUserId,
          {
            $addToSet: { followers: userId },
            $inc: { "account_info.total_followers": 1 },
          },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    res.status(200).json({
      message: "User followed successfully",
      total_followers: targetUser.account_info.total_followers + 1,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const unfollowUser = async (req, res) => {
  try {
    let userId = req.user;
    const { targetUserId, currentUserId = null } = req.body;

    if (currentUserId) {
      userId = currentUserId;
    }

    // Check if users exist
    const [user, targetUser] = await Promise.all([
      User.findById(userId),
      User.findById(targetUserId),
    ]);

    if (!user || !targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if actually following
    if (!user.following.includes(targetUserId)) {
      return res.status(400).json({ error: "Not following this user" });
    }

    // Remove relationships using transaction
    const session = await User.startSession();
    try {
      await session.withTransaction(async () => {
        // Update unfollowing user
        await User.findByIdAndUpdate(
          userId,
          {
            $pull: { following: targetUserId },
            $inc: { "account_info.total_following": -1 },
          },
          { session }
        );

        // Update unfollowed user
        await User.findByIdAndUpdate(
          targetUserId,
          {
            $pull: { followers: userId },
            $inc: { "account_info.total_followers": -1 },
          },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    res.status(200).json({
      message: "User unfollowed successfully",
      total_followers: targetUser.account_info.total_followers - 1,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const isFollowingUser = async (req, res) => {
  try {
    const userId = req.user;
    const { targetUserId } = req.body;

    // Check if users exist
    const [user, targetUser] = await Promise.all([
      User.findById(userId),
      User.findById(targetUserId),
    ]);

    if (!user || !targetUser) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if actually following
    const isFollowing = user.following.includes(targetUserId);

    res.status(200).json({ isFollowing });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get user's followers with pagination
export const getFollowers = async (req, res) => {
  try {
    const { user_id, page = 1 } = req.body;
    const limit = 5;
    const skip = (page - 1) * limit;

    const user = await User.findById(user_id).populate({
      path: "followers",
      select:
        "personal_info.fullname personal_info.username personal_info.profile_img",
      options: {
        skip,
        limit,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      followers: user.followers,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get users that the user is following with pagination
export const getFollowing = async (req, res) => {
  try {
    const { user_id, page = 1 } = req.body;
    const limit = 5;
    const skip = (page - 1) * limit;

    const user = await User.findById(user_id).populate({
      path: "following",
      select:
        "personal_info.fullname personal_info.username personal_info.profile_img",
      options: {
        skip,
        limit,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      following: user.following,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get total followers count
export const getFollowersCount = async (req, res) => {
  try {
    const { user_id } = req.body;

    const user = await User.findById(user_id).select("followers");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      totalDocs: user.followers.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get total following count
export const getFollowingCount = async (req, res) => {
  try {
    const { user_id } = req.body;

    const user = await User.findById(user_id).select("following");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      totalDocs: user.following.length,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// USERS MANAGEMENT
export const getUsers = async (req, res) => {
  try {
    const { page = 1, query = "" } = req.body;
    const limit = 10;
    const skip = (page - 1) * limit;

    let findQuery = {};
    if (query) {
      findQuery = {
        $or: [
          { "personal_info.username": new RegExp(query, "i") },
          { "personal_info.fullname": new RegExp(query, "i") },
        ],
      };
    }

    const users = await User.find(findQuery)
      .select(
        "personal_info.fullname personal_info.username personal_info.profile_img account_info"
      )
      .skip(skip)
      .limit(limit)
      .sort({ joinedAt: -1 });

    res.status(200).json({ users });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

export const getUsersCount = async (req, res) => {
  try {
    const { query = "" } = req.body;

    let findQuery = {};
    if (query) {
      findQuery = {
        $or: [
          { "personal_info.username": new RegExp(query, "i") },
          { "personal_info.fullname": new RegExp(query, "i") },
        ],
      };
    }

    const totalDocs = await User.countDocuments(findQuery);
    res.status(200).json({ totalDocs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// CHANGE USER ROLE
export const changeUserRole = async (req, res) => {
  try {
    const { userId, newRole } = req.body;

    // Validate role
    const validRoles = ["author", "moderator", "admin"];
    if (!validRoles.includes(newRole)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Don't allow changing admin's role
    if (user.role === "admin" && newRole !== "admin") {
      return res.status(403).json({ error: "Cannot change admin's role" });
    }

    // Update role
    await User.findByIdAndUpdate(userId, { role: newRole });

    res.status(200).json({
      message: "Role updated successfully",
      newRole,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// DELETE USER
export const deleteUser = async (req, res) => {
  try {
    const { userId } = req.body;

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Don't allow deleting another admin
    if (user.role === "admin") {
      return res.status(403).json({ error: "Cannot delete admin users" });
    }

    // Delete user and their related data
    const session = await User.startSession();
    try {
      await session.withTransaction(async () => {
        // Remove user from followers/following lists
        await User.updateMany(
          { $or: [{ followers: userId }, { following: userId }] },
          {
            $pull: {
              followers: userId,
              following: userId,
            },
            $inc: {
              "account_info.total_followers": -1,
              "account_info.total_following": -1,
            },
          },
          { session }
        );

        // Delete user's blogs
        if (user.blogs.length) {
          await Blog.deleteMany({ _id: { $in: user.blogs } }, { session });
        }

        // Finally delete the user
        await User.findByIdAndDelete(userId, { session });
      });

      res.status(200).json({ message: "User deleted successfully" });
    } finally {
      await session.endSession();
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};
