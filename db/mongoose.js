const mongoose = require('mongoose')
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://harshtripathih321:mLSDoecc4MyxahDH@buddy.gxymqtq.mongodb.net/'

mongoose.connect(mongoURI,{
    useUnifiedTopology:true,
    useNewUrlParser:true,
    useCreateIndex: true
}).then(()=> console.log("DataBase Connected")).catch((err)=>{
    console.log(err);
})
module.exports = { mongoose }  // Export the active connection.