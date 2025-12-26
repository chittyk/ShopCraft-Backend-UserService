const mongoose = require ('mongoose')

const connectDb = async () =>{
    try {
        await mongoose.connect(process.env.MONGODB_URI)
        .then((result) => {
            console.log('db connected successfuly')
        }).catch((err) => {
            console.log("db not connect due to : ",err)
            // process.exit(1)
        });
    } catch (error) {
        console.log("db not connected due to : " ,error)
        // process.exit(1)
    }
}

module.exports = connectDb