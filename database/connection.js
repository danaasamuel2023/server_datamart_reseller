const mongoose = require('mongoose');



const ConnectDB=()=>{
    const password = '0246783840Sa';
uri='mongodb+srv://datamartghana:0246783840sa@cluster0.s33wv2s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0'

    mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }).then(() => {
        console.log('Connected to MongoDB');
      }).catch(err => {
        console.error('Failed to connect to MongoDB', err);
      });
      
      

}

module.exports=ConnectDB;
