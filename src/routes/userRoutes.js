const express = require("express")
const { Register, Login, verifyOtp, forgetPassword, verifyForgotPassword, isBlockUser, getUsers, deleteUser, getProfile, editProfile } = require('../controller/userController')
const adminAuth = require("../middleware/adminAuth")
const auth = require("../middleware/auth")
// const { mountpath } = require("../app")

const userRouter = express.Router()

userRouter.post('/signup',Register)
userRouter.post('/login',Login)
userRouter.post('/verifySignUp',verifyOtp)
userRouter.post('/forgetPassword',forgetPassword)
userRouter.put('/updatePassword',verifyForgotPassword)
userRouter.get('/',adminAuth, getUsers)
userRouter.put('/isBlock/:userId',adminAuth,isBlockUser)
userRouter.get('/profile',auth,getProfile)
userRouter.put('/profile',auth,editProfile)
userRouter.delete('/:userId',adminAuth,deleteUser)


// userRouter.post('/google')

module.exports = userRouter