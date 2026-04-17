import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("authorization")?.replace("Bearer ", ""); // FIX: Bearer with space

    if (!token) {
      throw new ApiError(401, "Not authorized, token missing");
    }

    const decodedToken = jwt.verify(token.trim(), process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    if (!user) {
      throw new ApiError(401, "Not authorized, user not found");
    }

    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(401, "Not authorized, token failed");
  }
});

