require("dotenv").config();
const express = require("express");
const cors = require("cors");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
app.use(express.json());

app.use(cors({
  origin: "*",
  methods: ["GET","POST"],
  allowedHeaders: ["Content-Type","Authorization"]
}));

// 🔥 FIREBASE ADMIN
let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_KEY);
} catch (e) {
  console.error("FIREBASE_KEY ERROR");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

// 🔐 VERIFY TOKEN
async function verifyToken(req,res,next){
  try{
    const auth = req.headers.authorization;

    if(!auth || !auth.startsWith("Bearer "))
      return res.status(401).send("Unauthorized");

    const token = auth.split("Bearer ")[1];
    const decoded = await admin.auth().verifyIdToken(token);

    req.user = decoded;
    next();

  }catch(e){
    res.status(401).send("Invalid token");
  }
}

// 💳 RAZORPAY
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY,
  key_secret: process.env.RAZORPAY_SECRET,
});

// 🧾 CREATE ORDER
app.post("/create-order", verifyToken, async (req,res)=>{
  try{

    const { amount, items } = req.body;

    const order = await razorpay.orders.create({
      amount: amount * 100,
      currency: "INR",
      receipt: "rcpt_" + Date.now()
    });

    await db.collection("orders").doc(order.id).set({
      userId: req.user.uid,
      email: req.user.email,
      items,
      amount,
      status: "CREATED",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json(order);

  }catch(e){
    console.error(e);
    res.status(500).send("Create order failed");
  }
});

// ✅ VERIFY PAYMENT
app.post("/verify", verifyToken, async (req,res)=>{
  try{

    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if(expected !== razorpay_signature){
      return res.status(400).send("Invalid signature");
    }

    await db.collection("orders").doc(razorpay_order_id).update({
      status: "PAID",
      paymentId: razorpay_payment_id,
      paidAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success:true });

  }catch(e){
    res.status(500).send("Verify failed");
  }
});

// 🔥 ADMIN: GET ALL ORDERS
app.get("/admin/orders", verifyToken, async (req,res)=>{
  try{

    if(req.user.email !== "vedantbhalge2006@gmail.com"){
      return res.status(403).send("Not admin");
    }

    const snap = await db.collection("orders")
      .orderBy("createdAt","desc")
      .get();

    const data = snap.docs.map(d => ({
      id:d.id,
      ...d.data()
    }));

    res.json(data);

  }catch(e){
    res.status(500).send("Admin fetch failed");
  }
});

app.get("/", (req,res)=> res.send("Backend running"));

app.listen(process.env.PORT || 5000);
