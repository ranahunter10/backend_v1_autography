import { Router } from "express";
import {
  loginUser,
  logoutUser,
  registerUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateUserAvatar,
  updateAccountDetails,
  emailVerificationOtp,
  verifyEmail
} from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { emailVerificationMiddleware } from "../middlewares/nodemailer.middleware.js";


const userRouter = Router()

userRouter.post("/register",
  (req, res, next) => {
    // Handle both avatar and coverImage
    upload.fields([
      { name: 'avatar', maxCount: 1 },
      { name: 'coverImage', maxCount: 1 }
    ])(req, res, (err) => {
      if (err) {
        if (err.message.includes('Unexpected field')) {
          return res.status(400).json({
            success: false,
            message: err.message
          });
        }
        return next(err);
      }
      next();
    });
  },
  registerUser
);

userRouter.route("/login").post(upload.none(), loginUser)


//secured routesuserRuserRouter.route("/logout").post(verifyJWT, logoutUser)
userRouter.route("/refresh-token").post(refreshAccessToken)
userRouter.route("/change-password").post(verifyJWT, changeCurrentPassword)
userRouter.route("/current-user").get(verifyJWT, getCurrentUser)
userRouter.route("/update-account").patch(verifyJWT, updateAccountDetails)
userRouter.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)
userRouter.route("/send-verify-otp").post(emailVerificationMiddleware, emailVerificationOtp)
userRouter.route("/verify-account").post(emailVerificationMiddleware, verifyEmail)



export default userRouter