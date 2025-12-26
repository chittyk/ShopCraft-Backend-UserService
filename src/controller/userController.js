const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { transporter } = require("../config/nodemailer");
const otpMail = require("../mails/otp");
const Otp = require("../models/Otp");
const forgetPasswordOtpMail = require("../mails/forgetpass");

const Register = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ msg: "invalid cridentials" });
    const isUser = await User.findOne({ email });
    if (isUser) return res.status(409).json({ msg: "User Already Exist" });

    await Otp.deleteOne({ email });

    try {
      // generate otp
      const otp = Math.floor(100000 + Math.random() * 900000);

      // hash the otp
      const salt = await bcrypt.genSalt(10);
      const hashOtp = await bcrypt.hash(otp.toString(), salt);

      //send mail
      const mailOptions = otpMail(email, otp);
      await transporter.sendMail(mailOptions);
      console.log(` OTP sent to ${email} otp is : ${otp}`);

      await Otp.create({
        email,
        otp: hashOtp,
      });

      res.status(200).json({ msg: "OTP sent to your email" });
    } catch (error) {
      console.error(" Error sending email:", error);
      res.status(500).json({ error: "Failed to send OTP email" });
    }
  } catch (error) {
    console.log("error due to :", error);
    return res.status(502).json("server side error try again later");
  }
};

const verifyOtp = async (req, res) => {
  try {
    const { email, otp, password, name } = req.body;
    console.log(req.body);
    if (!email || !password || !name)
      return res.status(400).json({ msg: "invalid credentials" });

    const bkOtp = await Otp.findOne({ email });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ msg: "User already registered" });

    if (!bkOtp) return res.status(401).json("Otp expires !");

    const isOtp = await bcrypt.compare(otp, bkOtp.otp);
    if (!isOtp) return res.status(401).json({msg:"wrong otp try again"});

    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      email,
      password: hashPassword,
      name,
    });

    //delete  opt from db
    await Otp.deleteOne({ email });

    // create the jwt token
    const token = jwt.sign(
      {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.status(200).json({ msg: "User Created Successfully", token, newUser });
  } catch (error) {
    console.log(error);
    return res.status(502).json({ msg: "server error" });
  }
};

const Login = async (req, res) => {
  try {
    const { email, password } = req.body; 
    if (!email || !password)
      return res.status(400).json({ msg: "invalid cridentials " });
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ msg: "wrong user name or password" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "wrong user name or password" });
    //creating  token
    const token = jwt.sign(
      { id: user._id,
        name:user.name,
        email:user.email,
        role: user.role 
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );


    
    console.log(req.body);
    return res.status(200).json({
      msg: "User successfully logged in",
      user:{
        _id: user._id,
        name: user.name,
        email: user.email,
        
      },
      token,
    });
  } catch (error) {
    console.error("error due to :", error);
    return res.status(502).json({ msg: "server side error" });
  }
};

const forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res
        .status(400)
        .json({ msg: "Invalid credentials: Email required." });

    const user = await User.findOne({ email });
    if (!user)
      return res
        .status(404)
        .json({ msg: "User not found. Please sign up first." });

    // Check if OTP already exists (to prevent spam)
    const existingOtp = await Otp.findOne({ email });
    if (existingOtp)
      return res.status(429).json({
        msg: "OTP already sent. Please wait before requesting again.",
      });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Hash the OTP for security
    const salt = await bcrypt.genSalt(10);
    const hashOtp = await bcrypt.hash(otp.toString(), salt);

    // Prepare and send email
    const mailOptions = forgetPasswordOtpMail(email, otp);
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}: ${otp}`);

    // Store hashed OTP in DB
    await Otp.create({ email, otp: hashOtp });

    return res.status(200).json({ msg: "OTP sent to your email." });
  } catch (error) {
    console.error("Error during forgot password:", error);
    return res
      .status(500)
      .json({ msg: "Server error. Please try again later." });
  }
};

const verifyForgotPassword = async (req, res) => {
  try {
    const { otp, email, password } = req.body;

    if (!email || !password || !otp)
      return res
        .status(400)
        .json({ msg: "Invalid request. All fields required." });

    // Check OTP existence first
    const bkOtp = await Otp.findOne({ email });
    if (!bkOtp)
      return res.status(401).json({ msg: "OTP expired or not found!" });

    // Validate OTP
    const isOtpValid = await bcrypt.compare(otp.toString(), bkOtp.otp);
    if (!isOtpValid)
      return res.status(401).json({ msg: "Incorrect OTP. Please try again." });

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (!existingUser) return res.status(404).json({ msg: "User not found." });

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(password, salt);

    // Update password
    await User.updateOne({ email }, { $set: { password: hashPassword } });

    // Delete OTP after successful verification
    await Otp.deleteOne({ email });

    return res.status(200).json({ msg: "Password updated successfully." });
  } catch (error) {
    console.error("Error verifying forgot password:", error);
    return res
      .status(500)
      .json({ msg: "Server error. Please try again later." });
  }
};

const getUsers = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    if (!users) return res.status(401).json({ msg: "not user in list" });

    res.status(200).json({ users });
  } catch (error) {
    console.log("server error :", error);
    return res.status(502).json({ msg: "server error" });
  }
};

const isBlockUser = async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) return res.status(400).json({ msg: "User ID is required" });

    // Find the user first
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ msg: "User not found" });

    // Toggle the isBlock value
    user.isBlock = !user.isBlock;
    await user.save();

    res.status(200).json({
      msg: `User has been ${
        user.isBlock ? "blocked" : "unblocked"
      } successfully`,
      user,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

const getProfile = async (req, res) => {
  try {
    const id = req.userId; // from auth middleware
    console.log("User ID:", id);

    if (!id) return res.status(401).json({ msg: "Missing user ID" });

    const user = await User.findById(id).select("-password"); // correct way
    if (!user) return res.status(404).json({ msg: "User not found" });

    res.status(200).json({ user });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ msg: "Internal server error" });
  }
};

const editProfile = async (req, res) => {
  try {
    const id = req.userId;
    const update = req.body;
    if (!id) return res.status(401).json({ msg: "Missging user ID" });

    delete update.isBlock;
    delete update.role;

    const user = await User.findByIdAndUpdate(
      id,
      { $set: update },
      { new: true, runValidators: true }
    ).select("-password -isBlock");
    if (!user) return res.status(404).json({ msg: "User not found" });

    res.status(200).json({
      msg: "Profile updated successfully",
      user,
    });
  } catch (error) {
    console.error("Server error:", error);
    res.status(500).json({ msg: "Server error" });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId) return res.status(400).json({ msg: "User ID is required" });

    const user = await User.findByIdAndDelete(userId);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.status(200).json({ msg: "User deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
};

module.exports = {
  Register,
  Login,
  verifyOtp,
  forgetPassword,
  verifyForgotPassword,
  getUsers,
  isBlockUser,
  getProfile,
  editProfile,
  deleteUser,
};
