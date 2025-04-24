import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary, deleteOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import transporter from "../utils/nodemailer.js";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const forgotPasswordResetOtp = asyncHandler(async (req,res)=>{

     const email=req.body.email;

     if(!email){
      return new ApiError(400,"email is required")
     }
     try {
      const user= await User.findOne({email});

      if(!user){
        return new ApiError(400,"user not found")
      }

      const OTP=user.createPasswordResetToken();

      await user.save();

      const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject: "Password Reset OTP",
        text: `your Password Reset OTP is ${OTP}`,
      };
  
      await transporter.sendMail(mailOptions);
  
      return res
        .status(201)
        .json(new ApiResponse(200, "Password Reset otp sent on email "));
      
     } catch (error) {
      console.error("Real error:", error);
      throw new ApiError(400,"password reset error");
     }
});

const forgotPasswordReset=asyncHandler(async(req,res)=>{
    const {email,Otp,newPassword}=req.body;

    if (
      [email,Otp, newPassword].some((field) => field?.trim() === "")
    ) {
      throw new ApiError(400, "All fields are required");
    }

    try {
      const user = await User.findOne({email}).select(
        "+password +passwordResetToken +passwordResetExpires"
      );
      if (!user) {
        throw new ApiError(404, "User not found");
      }
  
      const hashedOtp = crypto.createHash("sha256").update(Otp).digest("hex");

      const otpFromDb = user.passwordResetToken;

      if (user.emailVerificationOtpExpiresAt < new Date()) {
        throw new ApiError(400, "OTP has expired");
      }
  
      if (!user.passwordResetToken || user.passwordResetToken !== hashedOtp) {
        throw new ApiError(400, "Invalid OTP");
      }

      user.password=newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
  
      await user.save();
  
      const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: user.email,
        subject: "welcome to Autography",
        text: `your password has been  resetted successfully `,
      };
  
      await transporter.sendMail(mailOptions);
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "password Reset successful"));

      
    } catch (error) {
      console.log(error);
      throw new ApiError(400,"password reset failed");
    }

});

const verifyEmail = asyncHandler(async (req, res) => {
  try {
    const { userId, Otp } = req.body;

    if (!userId || !Otp) {
      throw new ApiError(400, "User ID and OTP are required");
    }

    const user = await User.findById(userId).select(
      "+emailVerificationOtp +emailVerificationOtpExpiresAt"
    );
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const hashedOtp = crypto.createHash("sha256").update(Otp).digest("hex");

    // console.log("Raw OTP from request:", Otp);
    // console.log("Stored OTP in DB:", user.emailVerificationOtp);
    // console.log("OTP Expiry:", user.emailVerificationOtpExpiresAt);
    // console.log("Current Time:", new Date());

    const otpFromDb = user.emailVerificationOtp;

    if (user.emailVerificationOtpExpiresAt < new Date()) {
      throw new ApiError(400, "OTP has expired");
    }

    if (!user.emailVerificationOtp || user.emailVerificationOtp !== hashedOtp) {
      throw new ApiError(400, "Invalid OTP");
    }

    user.isAccountVerified = true;
    user.emailVerificationOtp = undefined;
    user.emailVerificationOtpExpiresAt = undefined;

    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "welcome to Autography",
      text: `your account has been successfully verified `,
    };

    await transporter.sendMail(mailOptions);
    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Email verified successfully"));
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }

    throw new ApiError(500, error.message || "Email verification failed");
  }
});

const emailVerificationOtp = asyncHandler(async (req, res) => {
  try {
    const userId = req.user?._id || req.body.userId;
    if (!userId) {
      throw new ApiError(400, "User ID not found");
    }
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    if (user.isAccountVerified) {
      return res
        .status(200)
        .json(new ApiResponse(200, {}, "Account already verified"));
    }
    // const OTP = String(Math.floor(100000 + Math.random() * 900000));

    const OTP = user.generateEmailVerificationOtp();

    // user.emailVerificationOtp = OTP;
    // user.emailVerificationOtpExpiresAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      text: `your Account Verification OTP is ${OTP}`,
    };

    await transporter.sendMail(mailOptions);

    return res
      .status(201)
      .json(new ApiResponse(200, "verification otp sent on email "));
  } catch (error) {
    throw new ApiError(401, error?.message || "email verification error");
  }
});

const registerUser = asyncHandler(async (req, res) => {

  const { fullName, email, username, password } = req.body;

  // console.log(req.body);

  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }



  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // console.log(req.files);
  // return ;

  // const avatarLocalPath = req.files?.avatar?.[0]?.path || req.file?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;

  let avatarLocalPath=null;
  if (
    req.files &&
    Array.isArray(req.files.avatar) &&
    req.files.avatar.length > 0
  ) {
    avatarLocalPath = req.files.avatar[0].path;
  }


  let coverImageLocalPath=null;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }


  // if (!avatarLocalPath) {
  //   throw new ApiError(400, "Avatar file is required .....");
  // }

  // const avatar = await uploadOnCloudinary(avatarLocalPath);
  // const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  // if (!avatar) {
  //   throw new ApiError(400, "Avatar file is required");
  // }


// const avatarLocalPath = req.files?.avatar?.[0]?.path || null;
// const coverImageLocalPath = req.files?.coverImage?.[0]?.path || null;
let avatar;
let coverImage;

if (avatarLocalPath) {
  avatar = await uploadOnCloudinary(avatarLocalPath);
}

if (coverImageLocalPath) {
  coverImage = await uploadOnCloudinary(coverImageLocalPath);
}

  const user = await User.create({
    fullName,
    avatar: avatar ?{
      public_id: avatar.public_id,
      url: avatar.secure_url,
    }:null,
    coverImage: coverImage ? {
      public_id: coverImage?.public_id,
      url: coverImage?.secure_url,
    }:null,
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  const mailOptions = {
    from: process.env.SENDER_EMAIL,
    to: email,
    subject: "welcome to Autography",
    text: `your account has been created with email_id ${email}`,
  };

  await transporter.sendMail(mailOptions);

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {

  const { email, username, password } = req.body;

  if (!username && !email) {
    throw new ApiError(400, "username or email is required");
  }

  // const user = await User.findOne({
  //   $or: [{ username }, { email }],
  // });

  const user = await User.findOne({
    $or: [{ username }, { email }],
  }).select("+password +loginAttempts +lockUntil");

  if (!user) {
    throw new ApiError(404, "User not exist");
  }

  if (user.isLocked) {
    throw new ApiError(423, "Account is temporarily locked. Try again later.");
  }

  if (user.lockUntil && user.lockUntil < Date.now()) {
    await user.resetLoginAttempts();
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    await user.incrementLoginAttempts();
    throw new ApiError(401, "Invalid user credentials");
  }

  if (user.loginAttempts > 0 || user.lockUntil) {
    await user.resetLoginAttempts();
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged In Successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id).select("+refreshToken");

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    // console.log("Incoming Token:", incomingRefreshToken);
    // console.log("Stored Token:", user.refreshToken);

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken,
            refreshToken,
          },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user?._id).select("+password");

  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "User fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;

  if (!fullName || !email) {
    throw new ApiError(400, "All fields are required");
  }


  const existingUser = await User.findById(req.user?._id);

  if (!existingUser) {
    throw new ApiError(404, "User not found");
  }
  
  const isEmailChanged = existingUser.email !== email;

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    {
      new: true,
    }
  );

  // console.log("hiii")

  if (isEmailChanged) {
    // console.log("i am here")
    user.isAccountVerified = false;
  }

  await user.save();

  res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);

  if (!avatar.url) {
    throw new ApiError(400, "Error while uploading on avatar");
  }

  const user = await User.findById(req.user._id).select("avatar");

  // delete old image
  const avatarToDelete = user.avatar.public_id;

  const updatedUser = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: {
          public_id: avatar.public_id,
          url: avatar.secure_url,
        },
      },
    },
    { new: true }
  ).select("-password");

  if (avatarToDelete && updatedUser.avatar.public_id) {
    await deleteOnCloudinary(avatarToDelete);
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, updatedUser, "Avatar image updated successfully")
    );
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;

  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image file is missing");
  }

  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!coverImage.url) {
    throw new ApiError(400, "Error while uploading on Cover image");
  }

  const user = await User.findById(req.user._id).select("coverImage");

  // delete old image
  const coverImageToDelete = user.coverImage.public_id;

  const updatedUser = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: {
          public_id: coverImage.public_id,
          url: coverImage.secure_url,
        },
      },
    },
    { new: true }
  ).select("-password");

  if (coverImageToDelete && updatedUser.coverImage.public_id) {
    await deleteOnCloudinary(coverImageToDelete);
  }

  return res
    .status(200)
    .json(
      new ApiResponse(200, updatedUser, "Cover image updated successfully")
    );
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  emailVerificationOtp,
  verifyEmail,
  forgotPasswordResetOtp,
  forgotPasswordReset
};
