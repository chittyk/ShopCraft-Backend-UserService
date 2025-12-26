// config/nodemailer.js
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.APP_PASS
  }
});

// Optional: verify connection once on startup
transporter.verify((error, success) => {
  if (error) {
    console.log("❌ Email transport error:", error);
  } else {
    console.log("📨 Email server ready to send messages");
  }
});

module.exports = { transporter }
