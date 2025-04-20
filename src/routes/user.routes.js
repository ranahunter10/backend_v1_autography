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


const router = Router()

router.post("/register", 
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

router.route("/login").post(upload.none(), loginUser)


//secured routes
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/change-password").post(verifyJWT, changeCurrentPassword)
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/update-account").patch(verifyJWT, updateAccountDetails)
router.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)
router.route("/send-verify-otp").post(emailVerificationMiddleware, emailVerificationOtp)
router.route("/verify-account").post(emailVerificationMiddleware, verifyEmail)



export default router