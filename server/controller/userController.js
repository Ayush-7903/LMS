import createError from "../utils/error.js";
import User from '../models/userModel.js';
import bcryptjs from 'bcryptjs';
import { v2 } from 'cloudinary';
import fs from 'fs/promises';
import sendMail from "../utils/sendMail.js";
import crypto from 'crypto';

export const signup = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return next(createError(401, "All input fields are required"));
        }

        const userExists = await User.findOne({ email });
        if (userExists) {
            return res.status(401).json({ success: false, message: "Email already exists" });
        }

        const user = new User({
            name,
            email,
            password,
            avatar: {
                public_id: email,
                secure_url: 'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_640.png'
            }
        });

        try {
            await user.validate();
        } catch (error) {
            const validationErrors = Object.values(error.errors).map(err => err.message);
            return res.status(400).json({ success: false, message: validationErrors.join(', ') });
        }

        if (req.file) {
            try {
                const result = await v2.uploader.upload(req.file.path, {
                    resource_type: 'image',
                    folder: 'lms',
                    width: 250,
                    height: 250,
                    gravity: 'faces',
                    crop: 'fill'
                });
                user.avatar.public_id = result.public_id;
                user.avatar.secure_url = result.secure_url;
                await fs.rm(req.file.path); // Ensure file is removed after upload
            } catch (error) {
                return next(createError(500, error.message || "File upload failed, please try again"));
            }
        }

        await user.save();
        user.password = undefined; // Hide password from response
        const token = await user.generateToken();
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return next(createError(401, "All input fields are required"));
        }

        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return next(createError(404, "User not found"));
        }

        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) {
            return next(createError(401, "Invalid email or password"));
        }

        const token = await user.generateToken();
        user.password = undefined; // Hide password from response
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        res.status(200).json({
            success: true,
            message: `Welcome back ${user.name}`,
            user
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const logout = (req, res, next) => {
    try {
        res.cookie('token', null, {
            httpOnly: true,
            maxAge: 0,
        });
        res.status(200).json({
            success: true,
            message: "User logged out successfully"
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const getProfile = async (req, res, next) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId);
        if (!user) {
            return next(createError(404, "User not found"));
        }
        res.status(200).json({
            success: true,
            message: 'User details',
            user
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const forgotPassword = async (req, res, next) => {
    const { email } = req.body;
    if (!email) {
        return next(createError(400, "Email is required"));
    }

    const user = await User.findOne({ email });
    if (!user) {
        return next(createError(404, "User not found"));
    }

    const resetToken = await user.generateResetToken();
    await user.save();

    const resetPasswordUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const subject = "Reset Password";
    const message = `You can reset your password by clicking <a href="${encodeURI(resetPasswordUrl)}" target="_blank">Reset your password</a>. If the above link does not work, copy-paste this link in a new tab: ${encodeURI(resetPasswordUrl)}. If you did not request this, kindly ignore.`;

    try {
        await sendMail(process.env.GMAIL_ID, email, subject, message);
        res.status(200).json({
            success: true,
            message: `Reset password email has been sent to ${email} successfully`
        });
    } catch (error) {
        user.forgotPasswordToken = undefined;
        user.forgotPasswordExpiry = undefined;
        await user.save();
        return next(createError(500, "Failed to send reset email. Please try again."));
    }
};

export const resetPassword = async (req, res, next) => {
    try {
        const { resetToken } = req.params;
        const { password } = req.body;

        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const user = await User.findOne({
            forgotPasswordToken: hashedToken,
            forgotPasswordExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return next(createError(400, "Token is invalid or expired. Please try again later."));
        }

        user.password = await bcryptjs.hash(password, 10); // Hash the new password
        user.forgotPasswordToken = undefined;
        user.forgotPasswordExpiry = undefined;
        await user.save();

        res.status(200).json({
            success: true,
            message: "Password reset successfully"
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const changePassword = async (req, res, next) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const userId = req.user.id;

        if (!oldPassword || !newPassword) {
            return next(createError(400, "All fields are required"));
        }

        const user = await User.findById(userId).select('+password');
        if (!user) {
            return next(createError(404, "User not found"));
        }

        const isMatch = await bcryptjs.compare(oldPassword, user.password);
        if (!isMatch) {
            return next(createError(401, "Invalid old password"));
        }

        user.password = await bcryptjs.hash(newPassword, 10); // Hash the new password
        await user.save();

        user.password = undefined; // Hide password from response
        res.status(200).json({
            success: true,
            message: "Password changed successfully"
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};

export const updateProfile = async (req, res, next) => {
    try {
        const { name } = req.body;
        const userId = req.user.id;
        const user = await User.findById(userId);

        if (!user) {
            return next(createError(404, "User not found"));
        }

        if (name) {
            user.name = name;
        }

        if (req.file) {
            // Remove the old avatar from Cloudinary
            if (user.avatar.public_id) {
                await v2.uploader.destroy(user.avatar.public_id, {
                    resource_type: 'image'
                });
            }

            try {
                const result = await v2.uploader.upload(req.file.path, {
                    resource_type: 'image',
                    folder: 'lms',
                    width: 250,
                    height: 250,
                    gravity: 'faces',server
                    
                });
                user.avatar.public_id = result.public_id;
                user.avatar.secure_url = result.secure_url;
                await fs.rm(req.file.path); // Ensure file is removed after upload
            } catch (error) {
                return next(createError(500, error.message || "File upload failed, please try again"));
            }
        }

        await user.save();
        res.status(200).json({
            success: true,
            message: "Profile updated successfully"
        });
    } catch (error) {
        return next(createError(500, error.message));
    }
};
export const deleteProfile = async (req, res, next) => {
    try {
        const userId = req.user.id
        const user = await User.findByIdAndDelete(userId)
        if (!user) {
            return next(createError(400, "user does not exists"))
        }
        await v2.uploader.destroy(user.avatar.public_id, {
            resource_type: 'image'
        })
        res.status(200).json({
            success: true,
            message: "profile deleted successfully"
        })
    } catch (error) {
        return next(createError(500, error.message))
    }
}