import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import { ROLES, DEFAULT_ROLE } from "../constants.js";

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowecase: true,
      trim: true,
      index: true
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    role: {
      type: String,
      enum: Object.values(ROLES),
      default: DEFAULT_ROLE

    },
    avatar: {
      type: {
        public_id: String,
        url: String //cloudinary url
      },
      required: true
    },
    coverImage: {
      type: {
        public_id: String,
        url: String //cloudinary url
      },
    },
    password: {
      type: String,
      required: [true, 'Password is required']
    },
     
    emailVerificationOtp:{
      type:String,
      default:""
    },
    emailVerificationOtpExpiresAt:{
      type:Number,
      default:0
    },
    emailresetOtp:{
      type:String,
      default:""
    },
    emailresetOtpExpiresAt:{
      type:Number,
      default:0
    },
    isAccountVerified:{
      type:Boolean,
      default:false
    },
    refreshToken: {
      type: String
    }

  },
  {
    timestamps: true
  }
)

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10)
  next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY
    }
  )
}
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,

    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY
    }
  )
}

export const User = mongoose.model("User", userSchema)