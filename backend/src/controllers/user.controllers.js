import { User } from '../models/user.models.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Error in generating tokens");
    }
}

const registerUser = asyncHandler(async (req, res) => {
    //get user data
    //verify if user exist
    //craete user
    //generate token
    //send response

    const { userName, email, password, fullName, phone, address } = req.body;

    if (!userName || !email || !password || !fullName) {
        throw new ApiError(400, "All fields are required");
    }

    const existedUser = await User.findOne({
        $or: [
            { userName }, { email }
        ]
    })

    if (existedUser) {
        throw new ApiError(409, "User already exist");
    }

    const user = await User.create({
        fullName,
        email,
        userName,
        password,
        phone,
        address
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken "
    )

    if (!createdUser) {
        throw new ApiError(500, "User not created");
    }

    return res.status(201).json(
        new ApiResponse(201, createdUser, "User created successfully")
    )
})

const loginUser = asyncHandler(async (req, res) => {
    //get user data
    //verify
    //check user exist
    //generate token
    //send response

    const { email, password, userName } = req.body;

    if (!(email || userName)) {
        throw new ApiError(400, "Email or username is required");
    }

    if (!password) {
        throw new ApiError(400, "Password is required");
    }

    const user = await User.findOne({
        $or: [
            { email },
            { userName }
        ]
    })

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.isBlocked) {
        throw new ApiError(403, "User is blocked");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(password);

    if (!isPasswordCorrect) {
        throw new ApiError(401, "Invalid credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie('accessToken', accessToken, options)
        .cookie('refreshToken', refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken
                },
                "User logged in successfully"
            )
        )
})

const logoutUser = asyncHandler(async (req, res) => {
    //clear cookies
    //send response

    await User.findByIdAndUpdate(
        req.user?._id,
        {
            refreshToken: undefined
        },
        {
            new: true,
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie('accessToken', options)
        .clearCookie('refreshToken', options)
        .json(
            new ApiResponse(
                200,
                null,
                "User logged out successfully"
            )
        )

})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(400, "Refresh token is required");
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

        const user = await User.findById(decodedToken.userId);

        if (!user) {
            throw new ApiError(404, "User not found");
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Invalid refresh token");
        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshToken(user._id);

        return res
            .status(200)
            .cookie('accessToken', accessToken, options)
            .cookie('refreshToken', newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        accessToken,
                        refreshToken: newRefreshToken
                    },
                    "Access token refreshed successfully"
                )
            )

    } catch (error) {
        throw new ApiError(401, "Invalid refresh token");
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    //get current password and new password
    //verify
    //check if current password is correct
    //update password
    //send response

    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user?._id);

    if (!(currentPassword && newPassword)) {
        throw new ApiError(400, "Current password and new password are required");
    }

    const isPasswordCorrect = await user.isPasswordCorrect(currentPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(401, "Current password is incorrect");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, "Password changed successfully")
        )


})

const updateUserProfile = asyncHandler(async (req, res) => {
    //get user data
    //verify
    //update user data
    //send response

    const { fullName, userName, email, phone, address } = req.body;

    if (!(fullName || userName || email || phone || address)) {
        throw new ApiError(400, "At least one field is required to update profile");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                userName,
                email,
                phone,
                address
            }
        },
        {
            new: true,
        }
    ).select("-password -refreshToken")

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "Profile updated successfully")
        )
})

const getCurrentUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select("-password -refreshToken");

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "User profile fetched successfully")
        )

})

const getAllUsers = asyncHandler(async (req, res) => {
    //get all users
    //send response

    const users = await User.find().select("-password -refreshToken");

    return res
        .status(200)
        .json(
            new ApiResponse(200, users, "All users fetched successfully")
        )

})

const blockUser = asyncHandler(async (req, res) => {
    //get user id from params
    //verify
    //block user
    //send response

    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.role === "admin") {
        throw new ApiError(403, "Cannot block admin user");
    }

    if (req.user?._id.toString() === userId) {
        throw new ApiError(403, "Cannot block yourself");
    }

    user.isBlocked = true;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "User blocked successfully")
        )
})

const unblockUser = asyncHandler(async (req, res) => {
    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
        throw new ApiError(404, "User not found");
    }


    if (req.user?._id.toString() === userId) {
        throw new ApiError(400, "Cannot unblock yourself");
    }

    if (!user.isBlocked) {
        throw new ApiError(400, "User is not blocked");
    }

    user.isBlocked = false;
    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "User unblocked successfully")
        )
})

const deleteUser = asyncHandler(async (req, res) => {
    //get user id from params
    //verify
    //delete user
    //send response

    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (user.role === "admin") {
        throw new ApiError(403, "Cannot delete admin user");
    }

    if (req.user?._id.toString() === userId) {
        throw new ApiError(403, "Cannot delete yourself");
    }

    await User.findByIdAndDelete(userId);


    return res
        .status(200)
        .json(
            new ApiResponse(200, null, "User deleted successfully")
        )
})


export {
    registerUser,
    generateAccessAndRefreshToken,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    updateUserProfile,
    getCurrentUserProfile,
    getAllUsers,
    blockUser,
    unblockUser,
    deleteUser
}