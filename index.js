const dns = require('node:dns');
dns.setServers(["8.8.8.8", "1.1.1.1"])
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');
const { createRemoteJWKSet, jwtVerify } = require('jose-cjs');

dotenv.config();
const app = express();
const port = process.env.PORT;

app.use(cors());
app.use(express.json());

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

// Middleware to verify if the token is valid and present
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized access: Token missing" });
    }
    const token = authHeader.split(" ")[1];
    if (!token || token === "undefined") {
        return res.status(401).json({ error: "Unauthorized access: Token string is invalid or undefined" });
    }
    try {
        const { payload } = await jwtVerify(token, JWKS);
        const verifiedUser = payload.user || payload.session?.user || payload;

        // console.log("JWT payload:", JSON.stringify(payload, null, 2));
        // console.log("Extracted user:", JSON.stringify(verifiedUser, null, 2));
        // console.log("Email being searched:", verifiedUser?.email);

        if (!verifiedUser || !verifiedUser.email) {
            return res.status(401).json({ error: "Unauthorized access: Token payload contains no user data" });
        }

        req.user = verifiedUser;
        next();
    }
    catch (error) {
        console.error("JWT verification error:", error);
        return res.status(401).json({ error: "Unauthorized access: Token expired or invalid" });
    }
};

async function run() {
    try {
        await client.connect();
        const db = client.db("omniflex");

        const classesCollection = db.collection("classes");
        const usersCollection = db.collection("user");
        const forumCollection = db.collection("forum");
        
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        //adding class by trainer
        app.post('/api/classes', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;
                const userName = req.user.name || "Unknown Trainer";

                // 1. Fetch user from database to verify current role and block status
                const dbUser = await usersCollection.findOne({ email: userEmail });

                // Rule check: Ensure the user exists in the DB
                if (!dbUser) {
                    return res.status(404).json({ error: "User profile not found in database" });
                }

                // Soft Block Rule: Blocked users cannot add classes
                if (dbUser.status === 'blocked') {
                    return res.status(403).json({ error: "Action restricted by Admin" });
                }

                // Role Check Rule: Only trainers or admins can create classes
                if (dbUser.role !== 'trainer' && dbUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Only trainers can create classes" });
                }

                const classData = req.body;

                // 2. Structuring the document exactly to assignment specifications
                const newClass = {
                    className: classData.className,
                    category: classData.category,
                    difficulty: classData.difficulty,
                    duration: classData.duration,
                    price: parseFloat(classData.price),
                    image: classData.image,
                    scheduleDays: classData.scheduleDays,
                    time: classData.time,
                    description: classData.description,

                    // Injected trainer credentials securely from our verified database check
                    trainerEmail: userEmail,
                    trainerName: dbUser.name || userName,

                    // Assignment defaults
                    bookingCount: 0,
                    status: "pending", // Must be pending until an Admin approves it
                    createdAt: new Date()
                };

                const result = await classesCollection.insertOne(newClass);
                res.status(201).json({ success: true, insertedId: result.insertedId });

            } catch (error) {
                console.error("Error saving class:", error);
                res.status(500).json({ error: "Internal server error saving class" });
            }
        });

        //loading class of trainer
        app.get('/api/trainer-classes', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // Find only classes matching this specific trainer's email
                const classes = await classesCollection.find({ trainerEmail: userEmail }).toArray();
                res.status(200).json(classes);
            } catch (error) {
                console.error("Error fetching trainer classes:", error);
                res.status(500).json({ error: "Failed to fetch classes" });
            }
        });

        // editing class of trainer
        app.patch('/api/classes/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const classId = req.params.id;
                const userEmail = req.user.email;
                const updateData = req.body;

                // Ensure the trainer updating this class is the one who created it
                const existingClass = await classesCollection.findOne({ _id: new ObjectId(classId) });
                if (!existingClass) {
                    return res.status(404).json({ error: "Class not found" });
                }
                if (existingClass.trainerEmail !== userEmail) {
                    return res.status(403).json({ error: "Forbidden: You do not own this class" });
                }

                const updatedDoc = {
                    $set: {
                        className: updateData.className,
                        category: updateData.category,
                        difficulty: updateData.difficulty,
                        duration: updateData.duration,
                        price: parseFloat(updateData.price),
                        time: updateData.time,
                        description: updateData.description,
                    }
                };

                await classesCollection.updateOne({ _id: new ObjectId(classId) }, updatedDoc);
                res.status(200).json({ success: true, message: "Class updated successfully" });
            } catch (error) {
                console.error("Error updating class:", error);
                res.status(500).json({ error: "Failed to update class" });
            }
        });

        // deleting class by trainer
        app.delete('/api/classes/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const classId = req.params.id;
                const userEmail = req.user.email;

                const existingClass = await classesCollection.findOne({ _id: new ObjectId(classId) });
                if (!existingClass) {
                    return res.status(404).json({ error: "Class not found" });
                }
                if (existingClass.trainerEmail !== userEmail) {
                    return res.status(403).json({ error: "Forbidden: You do not own this class" });
                }

                await classesCollection.deleteOne({ _id: new ObjectId(classId) });
                res.status(200).json({ success: true, message: "Class deleted successfully" });
            } catch (error) {
                console.error("Error deleting class:", error);
                res.status(500).json({ error: "Failed to delete class" });
            }
        });

    } finally {
        // Keep connection open
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});