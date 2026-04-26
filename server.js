require("dotenv").config();
const express = require("express");
const cors = require("cors");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
app.use(express.json());

/* ==============================
   ✅ FIXED CORS (IMPORTANT)
   ============================== */
app.use(cors({
  origin: true,
  credentials: true
}));

/* ==============================
   🔥 FIREBASE ADMIN
   ============================== */
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

/* ==============================
   🔐 AUTH MIDDLEWARE
   ============================== */
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send("Unauthorized");
    }

    const token = authHeader.split("Bearer ")[1];
    const decoded = await admin.auth().verifyIdToken(token);

    req.user = decoded;
    next();
  } catch (err) {
    console.error("Auth Error:", err);
    res.status(401).send("Invalid token");
  }
}

/* ==============================
   💳 RAZORPAY SETUP
   ============================== */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY,
  key_secret: process.env.RAZORPAY_SECRET,
});

/* ==============================
   🧾 CREATE ORDER
   ============================== */
app.post("/create-order", verifyToken, async (req, res) => {
  try {
    const { amount, items } = req.body;

    if (!amount || !items) {
      return res.status(400).send("Missing data");
    }

    const options = {
      amount: amount * 100,
      currency: "INR",
      receipt: "receipt_" + Date.now(),
    };

    const order = await razorpay.orders.create(options);

    // Save order
    await db.collection("orders").doc(order.id).set({
      userId: req.user.uid,
      items,
      amount,
      status: "CREATED",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json(order);

  } catch (err) {
    console.error("Create Order Error:", err);
    res.status(500).send("Error creating order");
  }
});

/* ==============================
   ✅ VERIFY PAYMENT
   ============================== */
app.post("/verify", verifyToken, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).send("Missing payment data");
    }

    const expected = crypto
      .createHmac("sha256", process.env.RAZORPAY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if (expected !== razorpay_signature) {
      return res.status(400).send("Invalid signature");
    }

    // Update order
    await db.collection("orders").doc(razorpay_order_id).update({
      status: "PAID",
      paymentId: razorpay_payment_id,
      paidAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true });

  } catch (err) {
    console.error("Verification Error:", err);
    res.status(500).send("Verification failed");
  }
});

/* ==============================
   🧪 HEALTH CHECK
   ============================== */
app.get("/", (req, res) => {
  res.send("Backend running");
});

/* ==============================
   🚀 START SERVER
   ============================== */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
