const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// 1. الاتصال بقاعدة البيانات الأمنة (MongoDB Atlas أو رابط Railway)
// استبدل الـ URI ده برابط قاعدة البيانات الخاص بك وتأكد من حفظه في Environment Variables على Railway
const MONGO_URI = process.env.MONGO_URI || "رابط_قاعدة_البيانات_هنا";

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to Secure Database Successfully!");
}).catch(err => {
    console.error("Database connection error:", err);
});

// 2. تصميم جدول (Schema) المستخدم لتخزين البيانات بأمان
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true } // هخزن الباسورد مشفر (Hashed)
});

const User = mongoose.model('User', userSchema);

// 3. مسار إنشاء حساب جديد (Register) مع تشفير الباسورد تلقائياً
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // التأكد إن الحقول مش فاضية
        if (!username || !password) {
            return res.status(400).json({ success: false, message: "الرجاء إدخال اسم المستخدم وكلمة المرور" });
        }

        // تشفير كلمة المرور بقوة (Salt Rounds = 10) لضمان الأمان التام
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            username,
            password: hashedPassword
        });

        await newUser.save();
        res.status(201).json({ success: true, message: "تم إنشاء الحساب بنجاح وأمان" });
    } catch (error) {
        res.status(500).json({ success: false, message: "اسم المستخدم مستخدم من قبل أو حدث خطأ في الخادم" });
    }
});

// 4. مسار تسجيل الدخول (Login) والتحقق من التشفير
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // البحث عن المستخدم في القاعدة
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ success: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
        }

        // مقارنة الباسورد المدخل مع الباسورد المشفر المخزن في الداتا بيز
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
        }

        res.status(200).json({ success: true, message: "تم تسجيل الدخول بنجاح" });
    } catch (error) {
        res.status(500).json({ success: false, message: "خطأ في الاتصال بالخادم" });
    }
});

// تشغيل السيرفر على البورت اللي بتحدده منصة Railway أو بورت محلي 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`RestGem Secure Server is running on port ${PORT}`);
});