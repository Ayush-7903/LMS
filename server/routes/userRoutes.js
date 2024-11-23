import express from "express";
import { 
    changePassword, 
    deleteProfile, 
    forgotPassword, 
    getProfile, 
    login, 
    logout, 
    resetPassword, 
    signup, 
    updateProfile 
} from "../controller/userController.js";
import { isLoggedIn } from "../middleware/authMiddleware.js";
import upload from "../middleware/multer.js";

const router = express.Router();

// User Signup
router.post("/signup", upload.single("avatar"), signup);

// User Login
router.post("/login", login);

// User Logout
router.get("/logout", logout);

// Get User Profile
router.get("/myprofile", isLoggedIn, getProfile);

// Forgot Password
router.post("/forgot-password", forgotPassword);

// Reset Password with Token
router.post("/reset/:resetToken", resetPassword);

// Change Password
router.put("/change-password", isLoggedIn, changePassword);

// Update Profile
router.put("/update", isLoggedIn, upload.single("avatar"), updateProfile);

// Delete Profile
router.delete("/delete-profile", isLoggedIn, deleteProfile);

export default router;
