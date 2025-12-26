const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema(
  {
    email: { 
        type: String,
        required: true, 
        unique: true 
    },  
    otp: { 
        type: String, 
        required: true 
    },
    createdAt: {
        type: Date, 
        default: Date.now, 
        expires: 180 
    } // 3 min TTL
  },
  { timestamps: true }
);

module.exports = mongoose.model("Otp", otpSchema);
