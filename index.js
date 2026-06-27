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
        const applicationsCollection = db.collection("trainer-applications");

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

        app.get('/api/trainer-overview', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // 1. Fetch trainer profile from DB
                const dbUser = await usersCollection.findOne({ email: userEmail });
                if (!dbUser) {
                    return res.status(404).json({ error: "Trainer profile not found" });
                }

                // 2. Aggregate total classes + total students enrolled (sum of bookingCount)
                const classStats = await classesCollection.aggregate([
                    { $match: { trainerEmail: userEmail } },
                    {
                        $group: {
                            _id: null,
                            totalClasses: { $sum: 1 },
                            totalStudents: { $sum: "$bookingCount" }
                        }
                    }
                ]).toArray();

                const totalClasses = classStats[0]?.totalClasses || 0;
                const totalStudents = classStats[0]?.totalStudents || 0;

                // 3. Count total forum posts by this trainer
                const totalForumPosts = await forumCollection.countDocuments({ authorEmail: userEmail });

                // 4. Fetch 3 most recent classes as preview
                const classesPreview = await classesCollection
                    .find({ trainerEmail: userEmail })
                    .sort({ createdAt: -1 })
                    .limit(3)
                    .toArray();

                // 5. Send unified response
                res.status(200).json({
                    profile: {
                        name: dbUser.name || req.user.name || "Trainer",
                        email: dbUser.email,
                        role: dbUser.role,
                        image: dbUser.image || null
                    },
                    stats: { totalClasses, totalStudents, totalForumPosts },
                    classesPreview
                });

            } catch (error) {
                console.error("Error loading trainer overview:", error);
                res.status(500).json({ error: "Failed to load trainer dashboard overview" });
            }
        });

        //admin

        const requireAdmin = async (req, res, next) => {
            try {
                const dbUser = await usersCollection.findOne({ email: req.user.email });
                if (!dbUser) return res.status(404).json({ error: "User not found" });
                if (dbUser.role !== 'admin') return res.status(403).json({ error: "Access forbidden: Admins only" });
                if (dbUser.status === 'blocked') return res.status(403).json({ error: "Action restricted by Admin" });
                req.dbUser = dbUser;
                next();
            } catch (error) {
                console.error("Admin middleware error:", error);
                return res.status(500).json({ error: "Internal server error in admin check" });
            }
        };

        // GET: All users (with optional search)
        app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {
            try {
                const search = req.query.search || "";
                const query = search
                    ? {
                        $or: [
                            { name: { $regex: search, $options: "i" } },
                            { email: { $regex: search, $options: "i" } },
                        ],
                    }
                    : {};
                const users = await usersCollection.find(query).sort({ createdAt: -1 }).toArray();
                res.status(200).json(users);
            } catch (error) {
                console.error("Error fetching users:", error);
                res.status(500).json({ error: "Failed to fetch users" });
            }
        });

        // PATCH: Block or Unblock a user
        app.patch('/api/admin/users/:id/status', verifyToken, requireAdmin, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const { status } = req.body;
                if (!["blocked", "active"].includes(status)) {
                    return res.status(400).json({ error: "Invalid status value" });
                }
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(req.params.id) },
                    { $set: { status, updatedAt: new Date() } }
                );
                if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
                res.status(200).json({ success: true, message: `User ${status === 'blocked' ? 'blocked' : 'unblocked'} successfully` });
            } catch (error) {
                console.error("Error updating user status:", error);
                res.status(500).json({ error: "Failed to update user status" });
            }
        });

        // PATCH: Promote a user to admin
        app.patch('/api/admin/users/:id/make-admin', verifyToken, requireAdmin, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(req.params.id) },
                    { $set: { role: "admin", updatedAt: new Date() } }
                );
                if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
                res.status(200).json({ success: true, message: "User promoted to Admin successfully" });
            } catch (error) {
                console.error("Error promoting user:", error);
                res.status(500).json({ error: "Failed to promote user" });
            }
        });

        // POST: Submit a trainer application
        app.post('/api/trainer-application', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // 1. Verify user exists in DB
                const dbUser = await usersCollection.findOne({ email: userEmail });
                if (!dbUser) {
                    return res.status(404).json({ error: "User profile not found in database" });
                }

                // 2. Block check
                if (dbUser.status === 'blocked') {
                    return res.status(403).json({ error: "Action restricted by Admin" });
                }

                // 3. Already a trainer or admin — no need to apply
                if (dbUser.role === 'trainer' || dbUser.role === 'admin') {
                    return res.status(400).json({ error: "You are already a trainer or admin." });
                }

                // 4. Check if they already have a pending application
                const existingApp = await applicationsCollection.findOne({
                    applicantEmail: userEmail,
                    status: "pending"
                });
                if (existingApp) {
                    return res.status(400).json({ error: "You already have a pending application." });
                }

                const { experience, specialty, bio } = req.body;

                // 5. Basic validation
                if (!experience || !specialty || !bio) {
                    return res.status(400).json({ error: "All fields are required." });
                }
                if (bio.trim().length < 30) {
                    return res.status(400).json({ error: "Bio must be at least 30 characters." });
                }

                // 6. Save application
                const newApplication = {
                    applicantName: dbUser.name,
                    applicantEmail: userEmail,
                    applicantImage: dbUser.image || null,
                    experience: Number(experience),
                    specialty,
                    bio: bio.trim(),
                    status: "pending", // pending | approved | rejected
                    adminFeedback: null,
                    appliedAt: new Date(),
                };

                const result = await applicationsCollection.insertOne(newApplication);
                res.status(201).json({ success: true, insertedId: result.insertedId });

            } catch (error) {
                console.error("Error submitting trainer application:", error);
                res.status(500).json({ error: "Internal server error submitting application" });
            }
        });

        // GET: Check current user's application status
        app.get('/api/trainer-application/status', verifyToken, async (req, res) => {
            try {
                const userEmail = req.user.email;

                // Find their most recent application (could be pending or rejected)
                const application = await applicationsCollection.findOne(
                    { applicantEmail: userEmail },
                    { sort: { appliedAt: -1 } } // most recent first
                );

                res.status(200).json({ application: application || null });
            } catch (error) {
                console.error("Error fetching application status:", error);
                res.status(500).json({ error: "Failed to fetch application status" });
            }
        });

        app.get('/api/admin/trainer-applications', verifyToken, async (req, res) => {
            try {
                const requesterEmail = req.user.email;

                // Verify admin role
                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                // Only return pending ones — decided ones are archived
                const applications = await applicationsCollection
                    .find({ status: "pending" })
                    .sort({ appliedAt: -1 })
                    .toArray();

                res.status(200).json(applications);
            } catch (error) {
                console.error("Error fetching trainer applications:", error);
                res.status(500).json({ error: "Failed to load trainer applications." });
            }
        });

        // PATCH: Admin approves or rejects a trainer application
        app.patch('/api/admin/trainer-applications/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const applicationId = req.params.id;
                const requesterEmail = req.user.email;
                const { action, feedback } = req.body; // action: "approve" | "reject"

                // Verify admin role
                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                // Find the application
                const application = await applicationsCollection.findOne({ _id: new ObjectId(applicationId) });
                if (!application) {
                    return res.status(404).json({ error: "Application not found." });
                }

                if (action === "approve") {
                    // 1. Update the application status to approved
                    await applicationsCollection.updateOne(
                        { _id: new ObjectId(applicationId) },
                        { $set: { status: "approved", adminFeedback: null, decidedAt: new Date() } }
                    );

                    // 2. Promote the user's role to trainer in omniflex.user collection
                    await usersCollection.updateOne(
                        { email: application.applicantEmail },
                        { $set: { role: "trainer", updatedAt: new Date() } }
                    );

                    return res.status(200).json({ success: true, message: "Application approved. User is now a trainer." });

                } else if (action === "reject") {
                    if (!feedback || feedback.trim().length === 0) {
                        return res.status(400).json({ error: "Feedback is required when rejecting an application." });
                    }

                    // Update application status to rejected with feedback
                    // The feedback will be shown to the user on their apply-trainer page
                    await applicationsCollection.updateOne(
                        { _id: new ObjectId(applicationId) },
                        {
                            $set: {
                                status: "rejected",
                                adminFeedback: feedback.trim(),
                                decidedAt: new Date()
                            }
                        }
                    );

                    return res.status(200).json({ success: true, message: "Application rejected with feedback." });

                } else {
                    return res.status(400).json({ error: "Invalid action. Must be 'approve' or 'reject'." });
                }

            } catch (error) {
                console.error("Error processing trainer application:", error);
                res.status(500).json({ error: "Failed to process application." });
            }
        });

        app.get('/api/admin/trainers', verifyToken, async (req, res) => {
            try {
                const requesterEmail = req.user.email;

                // Verify admin role
                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                // Fetch all users with role "trainer"
                const trainers = await usersCollection
                    .find({ role: "trainer" })
                    .sort({ createdAt: -1 })
                    .toArray();

                res.status(200).json(trainers);
            } catch (error) {
                console.error("Error fetching trainers:", error);
                res.status(500).json({ error: "Failed to load trainers." });
            }
        });

        // PATCH: Admin demotes a trainer back to user role
        app.patch('/api/admin/trainers/:id/demote', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const trainerId = req.params.id;
                const requesterEmail = req.user.email;

                // Verify admin role
                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                // Find the trainer
                const trainer = await usersCollection.findOne({ _id: new ObjectId(trainerId) });
                if (!trainer) {
                    return res.status(404).json({ error: "Trainer not found." });
                }
                if (trainer.role !== 'trainer') {
                    return res.status(400).json({ error: "This user is not a trainer." });
                }

                // Demote to user
                await usersCollection.updateOne(
                    { _id: new ObjectId(trainerId) },
                    { $set: { role: "user", updatedAt: new Date() } }
                );

                res.status(200).json({ success: true, message: "Trainer demoted to user." });
            } catch (error) {
                console.error("Error demoting trainer:", error);
                res.status(500).json({ error: "Failed to demote trainer." });
            }
        });

        app.get('/api/admin/classes', verifyToken, async (req, res) => {
            try {
                const requesterEmail = req.user.email;

                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                const allClasses = await classesCollection
                    .find({})
                    .sort({ createdAt: -1 })
                    .toArray();

                res.status(200).json(allClasses);
            } catch (error) {
                console.error("Error fetching all classes:", error);
                res.status(500).json({ error: "Failed to load classes." });
            }
        });

        // PATCH: Admin approves or rejects a class
        app.patch('/api/admin/classes/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const classId = req.params.id;
                const requesterEmail = req.user.email;
                const { status } = req.body; // "approved" | "rejected"

                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                if (!["approved", "rejected"].includes(status)) {
                    return res.status(400).json({ error: "Invalid status. Must be 'approved' or 'rejected'." });
                }

                const result = await classesCollection.updateOne(
                    { _id: new ObjectId(classId) },
                    { $set: { status, updatedAt: new Date() } }
                );

                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: "Class not found." });
                }

                res.status(200).json({ success: true, message: `Class ${status} successfully.` });
            } catch (error) {
                console.error("Error updating class status:", error);
                res.status(500).json({ error: "Failed to update class." });
            }
        });

        // DELETE: Admin permanently deletes a class
        app.delete('/api/admin/classes/:id', verifyToken, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const classId = req.params.id;
                const requesterEmail = req.user.email;

                const adminUser = await usersCollection.findOne({ email: requesterEmail });
                if (!adminUser || adminUser.role !== 'admin') {
                    return res.status(403).json({ error: "Access forbidden: Requires Administrator privileges." });
                }

                const result = await classesCollection.deleteOne({ _id: new ObjectId(classId) });

                if (result.deletedCount === 0) {
                    return res.status(404).json({ error: "Class not found." });
                }

                res.status(200).json({ success: true, message: "Class deleted successfully." });
            } catch (error) {
                console.error("Error deleting class:", error);
                res.status(500).json({ error: "Failed to delete class." });
            }
        });

        // GET: Admin fetches all forum posts
        app.get('/api/admin/forum-posts', verifyToken, requireAdmin, async (req, res) => {
            try {
                const posts = await forumCollection
                    .find({})
                    .sort({ createdAt: -1 })
                    .toArray();
                res.status(200).json(posts);
            } catch (error) {
                console.error("Error fetching all forum posts:", error);
                res.status(500).json({ error: "Failed to load forum posts." });
            }
        });

        // DELETE: Admin removes any forum post (no ownership check needed)
        app.delete('/api/admin/forum-posts/:id', verifyToken, requireAdmin, async (req, res) => {
            try {
                const { ObjectId } = require('mongodb');
                const result = await forumCollection.deleteOne({ _id: new ObjectId(req.params.id) });
                if (result.deletedCount === 0) {
                    return res.status(404).json({ error: "Post not found." });
                }
                res.status(200).json({ success: true, message: "Forum post deleted successfully." });
            } catch (error) {
                console.error("Error deleting forum post:", error);
                res.status(500).json({ error: "Failed to delete forum post." });
            }
        });

        // GET: Public classes page — approved only, with search, filter, pagination
        app.get('/api/classes/public', async (req, res) => {
            try {
                const search = req.query.search || "";
                const category = req.query.category || "";
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 9;
                const skip = (page - 1) * limit;

                // Base filter: only approved classes
                const query = { status: "approved" };

                // Search by class name
                if (search) {
                    query.className = { $regex: search, $options: "i" };
                }

                // Filter by category (case-insensitive exact match)
                if (category && category !== "All") {
                    query.category = { $regex: `^${category}$`, $options: "i" };
                }

                const total = await classesCollection.countDocuments(query);
                const classes = await classesCollection
                    .find(query)
                    .sort({ createdAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.status(200).json({
                    classes,
                    total,
                    page,
                    totalPages: Math.ceil(total / limit),
                });
            } catch (error) {
                console.error("Error fetching public classes:", error);
                res.status(500).json({ error: "Failed to load classes." });
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