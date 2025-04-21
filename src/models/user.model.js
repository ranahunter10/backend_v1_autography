import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from "crypto";
import validator from "validator";
import { ROLES, DEFAULT_ROLE } from "../constants.js";

const userSchema = new Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
      minlength: [3, "Username must be at least 3 characters"],
      maxlength: [30, "Username cannot exceed 30 characters"],
      validate: {
        validator: function (v) {
          return /^[a-zA-Z0-9_]+$/.test(v);
        },
        message: "Username can only contain letters, numbers, and underscores",
      },
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
      validate: {
        validator: validator.isEmail,
        message: "Please provide a valid email address",
      },
    },
    fullName: {
      type: String,
      // required: [true, "Full name is required"],
      trim: true,
      maxlength: [100, "Full name cannot exceed 100 characters"],
      validate: {
        validator: function (v) {
          return /^[a-zA-Z\u00C0-\u017F\s'-]+$/.test(v);
        },
        message: "Full name can only contain letters and basic punctuation",
      },
    },
    role: {
      type: String,
      enum: {
        values: Object.values(ROLES),
        message: "Invalid role specified",
      },
      default: DEFAULT_ROLE,
    },
    avatar: {
      type: {
        public_id: {
          type: String,
          required: [true, "Avatar public ID is required"],
        },
        url: {
          type: String,
          required: [true, "Avatar URL is required"],
          validate: {
            validator: validator.isURL,
            message: "Invalid avatar URL",
          },
        },
      },
      required: [true, "Avatar is required"],
      _id: false,
    },
    coverImage: {
      type: {
        public_id: String,
        url: {
          type: String,
          validate: {
            validator: validator.isURL,
            message: "Invalid cover image URL",
          },
        },
      },
      _id: false,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [12, "Password must be at least 12 characters"],
      validate: {
        validator: function (v) {
          return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/.test(
            v
          );
        },
        message:
          "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
      },
      select: false,
    },
    passwordChangedAt: {
      type: Date,
      select: false,
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
    passwordHistory: [
      {
        hash: {
          type: String,
          required: true,
        },
        changedAt: {
          type: Date,
          default: Date.now,
        },
        _id: false,
      },
    ],
    emailVerificationOtp: {
      type: String,
      select: false,
    },
    emailVerificationOtpExpiresAt: {
      type: Date,
      select: false,
    },
    isAccountVerified: {
      type: Boolean,
      default: false,
    },
    refreshToken: {
      type: String,
      select: false,
    },
    lastLogin: {
      type: Date,
    },
    loginAttempts: {
      type: Number,
      default: 0,
      select: false,
    },
    lockUntil: {
      type: Date,
      select: false,
    },
    status: {
      type: String,
      enum: ["active", "suspended", "deleted"],
      default: "active",
    },
    twoFactorSecret: {
      type: String,
      select: false,
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorRecoveryCodes: [
      {
        code: {
          type: String,
          select: false,
        },
        used: {
          type: Boolean,
          default: false,
        },
        _id: false,
      },
    ],
    devices: [
      {
        fingerprint: {
          type: String,
          required: true,
        },
        userAgent: String,
        ipAddress: String,
        lastUsed: Date,
        trusted: {
          type: Boolean,
          default: false,
        },
        _id: false,
      },
    ],
    connections: [
      {
        type: Schema.Types.ObjectId,
        ref: "Connection",
      },
    ],
    preferences: {
      theme: {
        type: String,
        enum: ["light", "dark", "system"],
        default: "system",
      },
      language: {
        type: String,
        default: "en",
      },
      journalPrivacy: {
        type: String,
        enum: ["private", "connections-only", "public"],
        default: "private",
      },
      notificationSettings: {
        email: {
          type: Boolean,
          default: true,
        },
        push: {
          type: Boolean,
          default: true,
        },
        inApp: {
          type: Boolean,
          default: true,
        },
      },
    },
    journals: [
      {
        type: Schema.Types.ObjectId,
        ref: "Journal",
      },
    ],
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: function (doc, ret) {
        delete ret.password;
        delete ret.passwordHistory;
        delete ret.emailVerificationOtp;
        delete ret.emailVerificationOtpExpiresAt;
        delete ret.refreshToken;
        delete ret.twoFactorSecret;
        delete ret.twoFactorRecoveryCodes;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        return ret;
      },
    },
    toObject: {
      virtuals: true,
      transform: function (doc, ret) {
        delete ret.password;
        delete ret.passwordHistory;
        delete ret.emailVerificationOtp;
        delete ret.emailVerificationOtpExpiresAt;
        delete ret.refreshToken;
        delete ret.twoFactorSecret;
        delete ret.twoFactorRecoveryCodes;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        return ret;
      },
    },
  }
);

// need better indexing (will think later)
userSchema.index({ username: 1, email: 1 });
userSchema.index({ "devices.fingerprint": 1 });
userSchema.index({ status: 1 });


// need improvements i guess (will come back to it later if causes trouble)
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    this.password = await bcrypt.hash(this.password, 12);
    if (this.passwordHistory) {
      this.passwordHistory.unshift({ hash: this.password });
      if (this.passwordHistory.length > 5) {
        this.passwordHistory = this.passwordHistory.slice(0, 5);
      }
    } else {
      this.passwordHistory = [{ hash: this.password }];
    }
    if (!this.isNew) {
      this.passwordChangedAt = Date.now() - 1000;
    }

    next();
  } catch (err) {
    next(err);
  }
});

// (--->>>>password change detection---> short and crisp )
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (!this.passwordChangedAt) return false;

  //to seconds
  const changedTimestamp = Math.floor(this.passwordChangedAt / 1000);
  
  // 1 sec buffer for safety
  return JWTTimestamp < changedTimestamp + 1;
};

userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

userSchema.methods.isPasswordInHistory = async function (newPassword) {
  for (const oldPassword of this.passwordHistory) {
    if (await bcrypt.compare(newPassword, oldPassword.hash)) {
      return true;
    }
  }
  return false;
};

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
      role: this.role,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
      algorithm: 'HS256'
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
      algorithm: 'HS256'
    }
  );
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 mins

  return resetToken;
};

userSchema.methods.generateEmailVerificationOtp = function () {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  this.emailVerificationOtp = crypto
    .createHash("sha256")
    .update(otp)
    .digest("hex");

  this.emailVerificationOtpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 mins

  // this.emailVerificationOtp=;

  return otp;
  // return this.save().then(() => otp);
};

userSchema.methods.incrementLoginAttempts = async function () {
  this.loginAttempts += 1;

  if (this.loginAttempts >= 5 && !this.lockUntil) {
    this.lockUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
  }

  await this.save();
};

userSchema.methods.resetLoginAttempts = async function () {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  await this.save();
};

userSchema.virtual("isLocked").get(function () {
  return this.lockUntil && this.lockUntil > Date.now();
});




export const User = mongoose.model("User", userSchema);
