require('dotenv').config();
const express = require('express');
const cors = require('cors');
const adminRoute = require('./Routes/adminRoute');
const barangRoute = require('./Routes/barangRoute');
const pembelianRoute = require('./Routes/pembelianRoute');
const detailPembelianRoute = require('./Routes/detailPembelianRoute');
const laporanRoute = require('./Routes/laporanRoute');
const userRoute = require('./Routes/userRoute');
const authRoute = require('./Routes/authRoute');


const app = express();
const port = process.env.PORT;

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads'));
app.use('/api/admin', adminRoute);
app.use('/api', barangRoute);
app.use('/api', pembelianRoute);
app.use('/api', detailPembelianRoute);
app.use('/api', laporanRoute);
app.use('/api/users', userRoute);
app.use('/api/auth', authRoute);


app.use((req, res) => {
  res.status(404).send("404 Not Found");
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});