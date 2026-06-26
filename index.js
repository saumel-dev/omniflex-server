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

        // POST ROUTE: Add a new Forum Post by trainer
        app.post('/api/forum-posts', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // 1. Fetch user from database to verify role and soft block status
                const dbUser = await usersCollection.findOne({ email: userEmail });
                if (!dbUser) {
                    return res.status(404).json({ error: "User profile not found in database" });
                }

                // Soft Block Rule Check
                if (dbUser.status === 'blocked') {
                    return res.status(403).json({ error: "Action restricted by Admin" });
                }

                // Role Check Rule: Only trainers or admins can publish forum articles
                if (dbUser.role !== 'trainer' && dbUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Only trainers and admins can create forum posts" });
                }

                const postData = req.body;

                // Server-side validation of text parameters
                if (!postData.description || postData.description.length < 100) {
                    return res.status(400).json({ error: "Description must be at least 100 characters long." });
                }

                // 2. Structuring the payload perfectly matching native collections fields
                const newPost = {
                    title: postData.title,
                    image: postData.image,
                    description: postData.description,

                    // Author Context parameters injected securely via verified token profile
                    authorName: dbUser.name || "Unknown Instructor",
                    authorEmail: userEmail,
                    authorRole: dbUser.role,
                    authorImage: dbUser.image || null, // Injects user profile picture if configured

                    // Interaction Defaults
                    likes: 0,
                    dislikes: 0,
                    createdAt: new Date()
                };

                const result = await forumCollection.insertOne(newPost);
                res.status(201).json({ success: true, insertedId: result.insertedId });

            } catch (error) {
                console.error("Error saving forum post natively:", error);
                res.status(500).json({ error: "Internal server error processing forum documentation" });
            }
        });

        // GET ROUTE: Fetch forum posts created exclusively by the logged-in trainer
        app.get('/api/trainer-forum-posts', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // Query the forum collection using the authorized email string
                const posts = await forumCollection.find({ authorEmail: userEmail }).toArray();
                res.status(200).json(posts);
            } catch (error) {
                console.error("Error loading trainer forum posts:", error);
                res.status(500).json({ error: "Failed to load your added forum posts." });
            }
        });

        // DELETE ROUTE: Remove a specific forum post matching the trainer's ownership authority
        app.delete('/api/forum-posts/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const postId = req.params.id;
                const userEmail = req.user.email;

                const existingPost = await forumCollection.findOne({ _id: new ObjectId(postId) });
                if (!existingPost) {
                    return res.status(404).json({ error: "Forum post structure not found" });
                }

                // Ownership Guard: Ensure the trainer deleting this post is the one who published it
                if (existingPost.authorEmail !== userEmail) {
                    return res.status(403).json({ error: "Forbidden: You do not own this forum post" });
                }

                await forumCollection.deleteOne({ _id: new ObjectId(postId) });
                res.status(200).json({ success: true, message: "Forum post deleted successfully" });
            } catch (error) {
                console.error("Error deleting forum post:", error);
                res.status(500).json({ error: "Failed to complete post elimination execution" });
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