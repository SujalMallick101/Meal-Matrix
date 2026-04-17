import { User } from "../models/user.models.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";

export const verifyAdmin = asyncHandler(async (req, res, next) => {
    if (req.user?.role !== "admin") {
        throw new ApiError(403, "Access denied, admin only");
    }
})