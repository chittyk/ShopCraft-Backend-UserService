// mails/otp.js
const otpMail = (to, otp) => {
  console.log("to and from ",to,process.env.EMAIL)
  return {
    from: process.env.EMAIL,
    to:to,
    subject: "Login OTP Code",
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2>Verification Code</h2>
        <p>Use the code below to complete your verification:</p>
        <h1 style="color: #4CAF50;">${otp}</h1>
        <p>This code will expire in 3 minutes.</p>
        <hr/>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
  };
};

module.exports = otpMail;
