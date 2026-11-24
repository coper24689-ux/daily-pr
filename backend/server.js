import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
dotenv.config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || "http://localhost:5173" }));
app.use(express.json({ limit: "1mb" }));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" }
}, { timestamps: true });
const reportRowSchema = new mongoose.Schema({
  product: { type: String, required: true },
  opening: { type: Number, default: 0, min: 0 },
  production: { type: Number, default: 0, min: 0 },
  returns: { type: Number, default: 0, min: 0 },
  dispatch: { type: Number, default: 0, min: 0 }
}, { _id: false });
const reportSchema = new mongoose.Schema({
  date: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  rows: { type: [reportRowSchema], default: [] },
  status: { type: String, enum: ["Draft", "Pending Review", "Approved"], default: "Draft" },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
  approvedAt: { type: Date, default: null }
}, { timestamps: true });
reportSchema.index({ date: 1, owner: 1 }, { unique: true });
const User = mongoose.model("User", userSchema);
const Report = mongoose.model("Report", reportSchema);

const PRODUCTS = [
"City Paver 50 mm (Gray)","City Paver 50 mm (Gray) (7000 PSI)","City Paver 50 mm (Top Red)","City Paver 50 mm (Top Black)",
"City Paver 60 mm (Gray 3000 PSI)","City Paver 60 mm (Gray 5000 PSI)","City Paver 60 mm (Top Red) 5000 PSI","City Paver 60 mm (Top Orange)",
"City 60 mm Yellow (5000 PSI)","City Paver 60 mm Black (7000 PSI)","City Paver 80 mm (Gray) (5000 PSI)","City Paver 80 mm (Top Red) SPC",
"City 80 mm Black 7000 PSI","Uni Paver 60 mm (Gray)","Uni Paver 60 mm (5000 PSI) Gray","Uni Paver 60 mm Top Red",
"Uni Paver 80 mm (Gray)","Uni Paver 80 mm (Top Red)","Uni Paver 80 mm (Top Black)","Sq Tile 8x8 50 mm (Gray)","Sq Tile 8x8 50 mm (Red)",
"Sq Tile 8x8 60 mm (Gray)","Quadra Paver","Quadro Paver 60 mm (Gray)","Quadro Paver 60 mm (Top Red)","I-Section 60 mm Gray",
"I-Section 60 mm Top Red","Cobal 60 mm Grey","Cobal 60 mm Red",'Curbstone 14" (B-Pair)','Curbstone 18" (B-Pair)',
"Solid Block 6x8x12","Solid Block 4x8x12","B-Pair Solid Block","K-2","Hallow Block","Hallow Block 4X8X16",
"Eco Brick - Red - Hole","Eco Brick - Grey - Hole","Eco Brick - Inter Lock","Eco Brick SC - Grey","Eco Brick - 3 Hole"
];
const tokenFor = user => jwt.sign({ id: user._id.toString(), username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: "12h" });
const auth = async (req,res,next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (!token) return res.status(401).json({ error: "Please sign in again." });
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(req.auth.id).select("_id username role");
    if (!user) return res.status(401).json({ error: "Account no longer exists." });
    req.user = user; next();
  } catch { return res.status(401).json({ error: "Session expired or invalid. Please sign in again." }); }
};
const adminOnly = (req,res,next) => req.user.role === "admin" ? next() : res.status(403).json({error:"Admin access required."});
const validDate = d => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d));
const cleanRows = rows => {
  if (!Array.isArray(rows)) throw new Error("Rows must be an array.");
  return rows.map(r => {
    if (!PRODUCTS.includes(r.product)) throw new Error("Unknown product: " + r.product);
    const clean = { product: r.product };
    for (const k of ["opening","production","returns","dispatch"]) {
      const n = Number(r[k] ?? 0);
      if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) throw new Error("Quantities must be non-negative whole numbers.");
      clean[k] = n;
    }
    return clean;
  });
};

app.get("/api/health", (_req,res) => res.json({status:"ok"}));
app.post("/api/auth/login", async (req,res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const user = await User.findOne({ username: new RegExp("^" + username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$","i") });
  if (!user || !(await bcrypt.compare(password,user.passwordHash))) return res.status(401).json({error:"Incorrect username or password."});
  res.json({ token: tokenFor(user), user:{id:user._id,username:user.username,role:user.role} });
});
app.get("/api/auth/me", auth, (req,res) => res.json({user:req.user}));
app.post("/api/auth/logout", auth, (_req,res) => res.json({message:"Signed out. Remove the token on the client."}));

app.get("/api/products", auth, (_req,res) => res.json(PRODUCTS));
app.get("/api/users", auth, adminOnly, async (_req,res) => {
  const users = await User.find().select("_id username role createdAt").sort({username:1});
  res.json(users);
});
app.post("/api/users", auth, adminOnly, async (req,res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const role = req.body.role === "admin" ? "admin" : "user";
  if (username.length < 3 || password.length < 6) return res.status(400).json({error:"Username must be at least 3 characters and password at least 6."});
  try {
    const user = await User.create({username,passwordHash:await bcrypt.hash(password,12),role});
    res.status(201).json({id:user._id,username:user.username,role:user.role});
  } catch(e) { if (e.code === 11000) return res.status(409).json({error:"That username already exists."}); throw e; }
});
app.delete("/api/users/:id", auth, adminOnly, async (req,res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({error:"User not found."});
  if (user.username.toLowerCase() === (process.env.ADMIN_USERNAME || "admin").toLowerCase()) return res.status(400).json({error:"The default admin cannot be removed."});
  if (user._id.equals(req.user._id)) return res.status(400).json({error:"You cannot remove your own account."});
  await User.deleteOne({_id:user._id});
  res.json({message:"User removed. Existing reports were preserved."});
});

app.get("/api/reports", auth, async (req,res) => {
  const filter = req.user.role === "admin" ? {} : {owner:req.user._id};
  const reports = await Report.find(filter).populate("owner","username").populate("reviewedBy","username").sort({date:-1});
  res.json(reports);
});
app.get("/api/reports/:date", auth, async (req,res) => {
  if (!validDate(req.params.date)) return res.status(400).json({error:"Invalid report date."});
  const filter = {date:req.params.date};
  if (req.user.role !== "admin") filter.owner = req.user._id;
  else if (req.query.owner) filter.owner = req.query.owner;
  const report = await Report.findOne(filter).populate("owner","username").populate("reviewedBy","username");
  res.json(report);
});
app.put("/api/reports/:date", auth, async (req,res) => {
  const date = req.params.date;
  if (!validDate(date)) return res.status(400).json({error:"Invalid report date."});
  if (req.user.role !== "user") return res.status(403).json({error:"Only user accounts can submit report data."});
  let rows;
  try { rows = cleanRows(req.body.rows); } catch(e) { return res.status(400).json({error:e.message}); }
  const status = req.body.status === "Pending Review" ? "Pending Review" : "Draft";
  const report = await Report.findOneAndUpdate(
    {date,owner:req.user._id},
    {$set:{rows,status},$setOnInsert:{date,owner:req.user._id}},
    {new:true,upsert:true,runValidators:true,setDefaultsOnInsert:true}
  ).populate("owner","username");
  res.json(report);
});
app.put("/api/reports/:id/review", auth, adminOnly, async (req,res) => {
  const status = req.body.status;
  if (!["Approved","Pending Review","Draft"].includes(status)) return res.status(400).json({error:"Invalid report status."});
  let update = {status};
  if (status === "Approved") { update.reviewedBy = req.user._id; update.approvedAt = new Date(); }
  const report = await Report.findByIdAndUpdate(req.params.id,{$set:update},{new:true,runValidators:true}).populate("owner","username").populate("reviewedBy","username");
  if (!report) return res.status(404).json({error:"Report not found."});
  res.json(report);
});
app.put("/api/reports/:id/correct", auth, adminOnly, async (req,res) => {
  let rows;
  try { rows = cleanRows(req.body.rows); } catch(e) { return res.status(400).json({error:e.message}); }
  const report = await Report.findByIdAndUpdate(req.params.id,{$set:{rows,status:"Approved",reviewedBy:req.user._id,approvedAt:new Date()}},{new:true,runValidators:true}).populate("owner","username").populate("reviewedBy","username");
  if (!report) return res.status(404).json({error:"Report not found."});
  res.json(report);
});

app.use((err,_req,res,_next) => { console.error(err); res.status(500).json({error:"Server error. Check backend logs."}); });
const start = async () => {
  if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) throw new Error("Set MONGODB_URI and JWT_SECRET in backend/.env");
  await mongoose.connect(process.env.MONGODB_URI);
  const adminName = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "Admin@123";
  if (!await User.exists({username:new RegExp("^"+adminName.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")+"$","i")})) {
    await User.create({username:adminName,passwordHash:await bcrypt.hash(adminPass,12),role:"admin"});
    console.log(`Created admin account: ${adminName}`);
  }
  await Report.syncIndexes();
  const port = process.env.PORT || 4000;
  app.listen(port,() => console.log(`DPR API running on port ${port}`));
};
start().catch(e => { console.error("Startup failed:",e.message); process.exit(1); });
