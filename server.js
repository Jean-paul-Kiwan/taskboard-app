// server.js  (MongoDB / Mongoose version)

// =======================================
// LOAD ENV VARIABLES
// =======================================
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const morgan = require("morgan");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const expressLayouts = require("express-ejs-layouts");
const mongoose = require("mongoose");

const MongoDBStore = require("connect-mongodb-session")(session);

const app = express();
const PORT = process.env.PORT || 3000;

const { sendEmail } = require("./emailService");

/* =======================================
   MONGO DB SETUP
======================================= */

const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error("❌ MONGO_URI is not defined in .env");
}
const store = new MongoDBStore({
  uri: MONGO_URI,
  collection: "sessions",
});
store.on("error", (error) => console.error("Session store error:", error));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-dev-key",
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

// Simple async wrapper for routes/middleware
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Connect to MongoDB, then start server
async function startServer() {
  try {
    if (!MONGO_URI) {
      throw new Error("MONGO_URI missing from environment variables");
    }

    await mongoose.connect(MONGO_URI, {
      // options optional in modern mongoose
      // useNewUrlParser: true,
      // useUnifiedTopology: true,
    });
    console.log("✅ Connected to MongoDB");

    app.listen(PORT, () => {
      console.log(`🚀 TaskBoard running on port ${PORT}`);
    });
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }
}

/* =======================================
   MONGOOSE SCHEMAS & MODELS
======================================= */

const { Schema, model, Types } = mongoose;

// USERS
const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
  },
  { timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

const User = model("User", userSchema);

// WORKSPACES
const workspaceSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    created_by: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

const Workspace = model("Workspace", workspaceSchema);

// WORKSPACE MEMBERS
const workspaceMemberSchema = new Schema(
  {
    workspace_id: { type: Schema.Types.ObjectId, ref: "Workspace", required: true },
    user_id: { type: Schema.Types.ObjectId, ref: "User", required: true },
    role: {
      type: String,
      enum: ["owner", "member"],
      default: "member",
    },
    joined_at: { type: Date, default: Date.now },
  },
  {}
);

// unique pair workspace + user
workspaceMemberSchema.index({ workspace_id: 1, user_id: 1 }, { unique: true });

const WorkspaceMember = model("WorkspaceMember", workspaceMemberSchema);

// TASKS
const taskSchema = new Schema(
  {
    workspace_id: { type: Schema.Types.ObjectId, ref: "Workspace", required: true },
    created_by: { type: Schema.Types.ObjectId, ref: "User", required: true },
    assigned_to: { type: Schema.Types.ObjectId, ref: "User" },
    title: { type: String, required: true, trim: true },
    description: { type: String },
    status: {
      type: String,
      enum: ["todo", "in_progress", "paused", "done"],
      default: "todo",
    },
    priority: {
      type: String,
      enum: ["low", "medium", "high", "urgent"],
      default: "medium",
    },
    tag: { type: String },
    due_date: { type: Date },
  },
  {
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
  }
);

const Task = model("Task", taskSchema);

// INVITATIONS
const invitationSchema = new Schema(
  {
    workspace_id: { type: Schema.Types.ObjectId, ref: "Workspace", required: true },
    inviter_id: { type: Schema.Types.ObjectId, ref: "User", required: true },
    invitee_id: { type: Schema.Types.ObjectId, ref: "User", required: true },
    status: {
      type: String,
      enum: ["pending", "accepted", "rejected"],
      default: "pending",
    },
  },
  { timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

const Invitation = model("Invitation", invitationSchema);

// NOTIFICATIONS
const notificationSchema = new Schema(
  {
    user_id: { type: Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, required: true }, // invite, invite_accepted, task_update, task_done, assignment, info
    message: { type: String, required: true },
    is_read: { type: Boolean, default: false },
  },
  { timestamps: { createdAt: "created_at", updatedAt: "updated_at" } }
);

const Notification = model("Notification", notificationSchema);

/* =======================================
   APP CONFIG
======================================= */

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(expressLayouts);
app.set("layout", "layout");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use(morgan("dev"));

/* =======================================
   HELPERS
======================================= */

// Create notification document
async function createNotification(userId, type, message) {
  if (!userId) return;
  try {
    await Notification.create({
      user_id: userId,
      type,
      message,
    });
  } catch (err) {
    console.error("Notification error:", err);
  }
}

// Global locals: currentUser, flash messages, unread notifications, workspace name
app.use(
  asyncHandler(async (req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    res.locals.error = req.session.error || null;
    res.locals.success = req.session.success || null;
    delete req.session.error;
    delete req.session.success;

    if (req.session.user) {
      const userId = req.session.user.id;

      const unreadCount = await Notification.countDocuments({
        user_id: userId,
        is_read: false,
      });

      res.locals.unreadCount = unreadCount || 0;

      if (req.session.currentWorkspaceId) {
        const ws = await Workspace.findById(req.session.currentWorkspaceId);
        res.locals.currentWorkspaceName = ws ? ws.name : null;
      } else {
        res.locals.currentWorkspaceName = null;
      }
    } else {
      res.locals.unreadCount = 0;
      res.locals.currentWorkspaceName = null;
    }

    next();
  })
);

/* =======================================
   MIDDLEWARE
======================================= */

function authRequired(req, res, next) {
  if (!req.session.user) {
    req.session.error = "Please log in first.";
    return res.redirect("/login");
  }
  next();
}

// Async middleware with workspace + membership check
const workspaceRequired = asyncHandler(async (req, res, next) => {
  if (!req.session.user) {
    req.session.error = "Please log in first.";
    return res.redirect("/login");
  }

  const wsId = req.session.currentWorkspaceId;
  if (!wsId) {
    req.session.error = "Select or create a workspace first.";
    return res.redirect("/workspaces");
  }

  const membership = await WorkspaceMember.findOne({
    workspace_id: wsId,
    user_id: req.session.user.id,
  }).populate("workspace_id");

  if (!membership || !membership.workspace_id) {
    req.session.currentWorkspaceId = null;
    req.session.error = "You are no longer a member of that workspace.";
    return res.redirect("/workspaces");
  }

  const workspace = membership.workspace_id; // populated object

  req.currentWorkspace = {
    id: workspace._id.toString(),
    role: membership.role,
    workspace: {
      id: workspace._id.toString(),
      name: workspace.name,
      created_by: workspace.created_by,
      created_at: workspace.created_at,
    },
  };

  next();
});

/* =======================================
   ROUTES: HOME / AUTH
======================================= */

// Home redirect
app.get(
  "/",
  asyncHandler(async (req, res) => {
    if (req.session.user) {
      if (req.session.currentWorkspaceId) {
        return res.redirect("/tasks");
      }
      return res.redirect("/workspaces");
    }
    return res.redirect("/login");
  })
);

// ---- Signup ----
app.get("/signup", (req, res) => {
  const error = res.locals.error;
  const success = res.locals.success;
  res.render("signup", {
    title: "Create Account",
    error,
    success,
  });
});

app.post(
  "/signup",
  asyncHandler(async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
      req.session.error = "All fields are required.";
      return res.redirect("/signup");
    }

    const cleanedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanedEmail)) {
      req.session.error = "Please enter a valid email address.";
      return res.redirect("/signup");
    }

    if (password !== confirmPassword) {
      req.session.error = "Passwords do not match.";
      return res.redirect("/signup");
    }

    if (password.length < 6) {
      req.session.error = "Password must be at least 6 characters long.";
      return res.redirect("/signup");
    }

    try {
      const existing = await User.findOne({ email: cleanedEmail });
      if (existing) {
        req.session.error = "An account with this email already exists.";
        return res.redirect("/signup");
      }

      const hash = await bcrypt.hash(password, 10);
      const user = await User.create({
        name: name.trim(),
        email: cleanedEmail,
        password: hash,
      });

      req.session.user = {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
      };

      // 📧 EMAIL — Welcome on signup
      try {
        await sendEmail({
          to: user.email,
          subject: `Welcome to TaskBoard, ${user.name}! 🎉`,
          message: `Hey ${user.name}, your TaskBoard account is ready.\n\nYou can now create your first workspace and start adding tasks.`,
        });
      } catch (e) {
        console.error("Welcome email error:", e);
      }

      req.session.success = "Welcome to TaskBoard! Create your first workspace.";
      return res.redirect("/workspaces");
    } catch (err) {
      console.error("Signup error:", err);
      req.session.error = "Something went wrong. Please try again.";
      return res.redirect("/signup");
    }
  })
);

// ---- Login ----
app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

app.post(
  "/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
      req.session.error = "Email and password are required.";
      return res.redirect("/login");
    }

    try {
      const cleanedEmail = email.trim().toLowerCase();
      const user = await User.findOne({ email: cleanedEmail });

      if (!user) {
        req.session.error = "Invalid email or password.";
        return res.redirect("/login");
      }

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) {
        req.session.error = "Invalid email or password.";
        return res.redirect("/login");
      }

      req.session.user = {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
      };

      // 📧 EMAIL — Login notification
      try {
        await sendEmail({
          to: user.email,
          subject: "New login to your TaskBoard account",
          message: `Hi ${user.name},\n\nYou just logged into TaskBoard on ${new Date().toLocaleString()}.\nIf this wasn't you, please reset your password.`,
        });
      } catch (e) {
        console.error("Login email error:", e);
      }

      // default workspace
      const membership = await WorkspaceMember.findOne({
        user_id: user._id,
      }).sort({ joined_at: 1 });

      if (membership) {
        req.session.currentWorkspaceId = membership.workspace_id.toString();
        req.session.success = "Welcome back!";
        return res.redirect("/tasks");
      } else {
        req.session.currentWorkspaceId = null;
        req.session.success = "Welcome back! Create or join a workspace.";
        return res.redirect("/workspaces");
      }
    } catch (err) {
      console.error("Login error:", err);
      req.session.error = "Something went wrong. Please try again.";
      return res.redirect("/login");
    }
  })
);

// ---- Logout ----
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

/* =======================================
   ROUTES: WORKSPACES
======================================= */

// List workspaces for the current user
app.get(
  "/workspaces",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;

    const memberships = await WorkspaceMember.find({
      user_id: userId,
    })
      .populate("workspace_id")
      .sort({ joined_at: -1 });

    const formatted = memberships
      .filter((m) => m.workspace_id)
      .map((m) => ({
        id: m.workspace_id._id.toString(),
        name: m.workspace_id.name,
        created_at: m.workspace_id.created_at,
        role: m.role,
      }));

    res.render("workspaces", {
      title: "Your Workspaces",
      memberships: formatted,
      currentWorkspaceId: req.session.currentWorkspaceId || null,
    });
  })
);

// Create a new workspace
app.post(
  "/workspaces",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const { name } = req.body;

    if (!name || name.trim() === "") {
      req.session.error = "Workspace name is required.";
      return res.redirect("/workspaces");
    }

    const workspace = await Workspace.create({
      name: name.trim(),
      created_by: userId,
    });

    await WorkspaceMember.create({
      workspace_id: workspace._id,
      user_id: userId,
      role: "owner",
    });

    req.session.currentWorkspaceId = workspace._id.toString();
    req.session.success = `Workspace "${name.trim()}" created.`;

    res.redirect("/tasks");
  })
);

// Switch active workspace
app.post(
  "/workspaces/:id/switch",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const workspaceId = req.params.id;

    const membership = await WorkspaceMember.findOne({
      workspace_id: workspaceId,
      user_id: userId,
    });

    if (!membership) {
      req.session.error = "You are not a member of that workspace.";
      return res.redirect("/workspaces");
    }

    req.session.currentWorkspaceId = workspaceId;
    req.session.success = "Workspace switched.";
    res.redirect("/tasks");
  })
);

// Invite user to workspace (owner only)
app.post(
  "/workspaces/:id/invite",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const currentUser = req.session.user;
    const workspace = req.currentWorkspace.workspace;

    if (currentUser.id !== workspace.created_by.toString()) {
      req.session.error = "Only the workspace owner can invite members.";
      return res.redirect("/workspaces");
    }

    const { email } = req.body;
    if (!email) {
      req.session.error = "Email is required.";
      return res.redirect("/workspaces");
    }

    const cleanedEmail = email.trim().toLowerCase();
    const invitee = await User.findOne({ email: cleanedEmail });

    if (!invitee) {
      req.session.error =
        "No existing user with this email. Ask them to sign up first.";
      return res.redirect("/workspaces");
    }

    // already member?
    const isMember = await WorkspaceMember.findOne({
      workspace_id: workspace.id,
      user_id: invitee._id,
    });

    if (isMember) {
      req.session.error = "User is already a member of this workspace.";
      return res.redirect("/workspaces");
    }

    // pending invite?
    const existingInvite = await Invitation.findOne({
      workspace_id: workspace.id,
      inviter_id: currentUser.id,
      invitee_id: invitee._id,
      status: "pending",
    });

    if (existingInvite) {
      req.session.error = "You already have a pending invitation for this user.";
      return res.redirect("/workspaces");
    }

    await Invitation.create({
      workspace_id: workspace.id,
      inviter_id: currentUser.id,
      invitee_id: invitee._id,
      status: "pending",
    });

    await createNotification(
      invitee._id,
      "invite",
      `${currentUser.name} invited you to join workspace "${workspace.name}".`
    );

    await createNotification(
      currentUser.id,
      "info",
      `Invitation sent to ${invitee.name} for workspace "${workspace.name}".`
    );

    // 📧 EMAIL — Workspace invitation
    try {
      await sendEmail({
        to: invitee.email,
        subject: `Workspace invitation: ${workspace.name}`,
        message: `${currentUser.name} invited you to join the workspace "${workspace.name}" on TaskBoard.\n\nLog in to your account to accept or reject the invitation.`,
      });
    } catch (e) {
      console.error("Invite email error:", e);
    }

    req.session.success = "Invitation sent.";
    res.redirect("/workspaces");
  })
);

/* =======================================
   ROUTES: INVITATIONS & NOTIFICATIONS
======================================= */

// Notifications & invitations page
app.get(
  "/notifications",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;

    const pendingInvites = await Invitation.find({
      invitee_id: userId,
      status: "pending",
    })
      .populate("workspace_id")
      .populate("inviter_id")
      .sort({ created_at: -1 });

    const formattedInvites = pendingInvites.map((i) => ({
      id: i._id.toString(),
      created_at: i.created_at,
      workspace_name: i.workspace_id ? i.workspace_id.name : "Workspace",
      inviter_name: i.inviter_id ? i.inviter_id.name : "Someone",
    }));

    const notes = await Notification.find({ user_id: userId })
      .sort({ created_at: -1 })
      .limit(100)
      .lean();

    res.render("notifications", {
      title: "Notifications",
      pendingInvites: formattedInvites,
      notifications: notes,
    });
  })
);

// Accept invitation
app.post(
  "/invitations/:id/accept",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const invId = req.params.id;

    const inv = await Invitation.findOne({
      _id: invId,
      invitee_id: userId,
      status: "pending",
    })
      .populate("workspace_id")
      .populate("inviter_id");

    if (!inv || !inv.workspace_id || !inv.inviter_id) {
      req.session.error = "Invitation not found or already handled.";
      return res.redirect("/notifications");
    }

    const workspace = inv.workspace_id;

    const existingMember = await WorkspaceMember.findOne({
      workspace_id: workspace._id,
      user_id: userId,
    });

    if (!existingMember) {
      await WorkspaceMember.create({
        workspace_id: workspace._id,
        user_id: userId,
        role: "member",
      });
    }

    inv.status = "accepted";
    await inv.save();

    await createNotification(
      inv.inviter_id._id,
      "invite_accepted",
      `${req.session.user.name} accepted your invitation to "${workspace.name}".`
    );

    // 📧 EMAIL — Invite accepted
    try {
      await sendEmail({
        to: inv.inviter_id.email,
        subject: `Invitation accepted: ${workspace.name}`,
        message: `${req.session.user.name} accepted your invitation to join the workspace "${workspace.name}".`,
      });
    } catch (e) {
      console.error("Invite accepted email error:", e);
    }

    req.session.currentWorkspaceId = workspace._id.toString();
    req.session.success = `You joined workspace "${workspace.name}".`;

    res.redirect("/tasks");
  })
);

// Reject invitation
app.post(
  "/invitations/:id/reject",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const invId = req.params.id;

    const inv = await Invitation.findOne({
      _id: invId,
      invitee_id: userId,
      status: "pending",
    })
      .populate("workspace_id")
      .populate("inviter_id");

    if (!inv || !inv.workspace_id || !inv.inviter_id) {
      req.session.error = "Invitation not found or already handled.";
      return res.redirect("/notifications");
    }

    inv.status = "rejected";
    await inv.save();

    await createNotification(
      inv.inviter_id._id,
      "invite_rejected",
      `${req.session.user.name} rejected your invitation to "${inv.workspace_id.name}".`
    );

    // (Optional) could also email inviter on rejection if you want

    req.session.success = "Invitation rejected.";
    res.redirect("/notifications");
  })
);

// Mark single notification as read
app.post(
  "/notifications/:id/read",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const noteId = req.params.id;

    await Notification.updateOne(
      { _id: noteId, user_id: userId },
      { $set: { is_read: true } }
    );

    res.redirect("/notifications");
  })
);

// Mark all notifications as read
app.post(
  "/notifications/read-all",
  authRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    await Notification.updateMany(
      { user_id: userId },
      { $set: { is_read: true } }
    );
    res.redirect("/notifications");
  })
);

/* =======================================
   ROUTES: TASKS
======================================= */

// List tasks in current workspace
app.get(
  "/tasks",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const currentUser = req.session.user;
    const workspace = req.currentWorkspace.workspace;

    const tasks = await Task.find({ workspace_id: workspace.id })
      .populate("assigned_to")
      .sort({ created_at: -1 });

    const columns = {
      todo: [],
      in_progress: [],
      paused: [],
      done: [],
    };

    tasks.forEach((t) => {
      const statusKey = t.status || "todo";
      const taskObj = {
        id: t._id.toString(),
        workspace_id: t.workspace_id,
        created_by: t.created_by,
        assigned_to: t.assigned_to ? t.assigned_to._id.toString() : null,
        assignee_name: t.assigned_to ? t.assigned_to.name : null,
        title: t.title,
        description: t.description,
        status: t.status,
        priority: t.priority,
        tag: t.tag,
        due_date: t.due_date,
        created_at: t.created_at,
        updated_at: t.updated_at,
      };
      if (!columns[statusKey]) columns[statusKey] = [];
      columns[statusKey].push(taskObj);
    });

    const stats = {
      total: tasks.length,
      todo: columns.todo.length,
      in_progress: columns.in_progress.length,
      paused: columns.paused.length,
      done: columns.done.length,
    };

    const membersDocs = await WorkspaceMember.find({
      workspace_id: workspace.id,
    })
      .populate("user_id")
      .sort({ "user_id.name": 1 });

    const members = membersDocs
      .filter((m) => m.user_id)
      .map((m) => ({
        id: m.user_id._id.toString(),
        name: m.user_id.name,
        role: m.role,
      }));

    res.render("tasks", {
      title: workspace.name + " – Tasks",
      columns,
      stats,
      members,
      workspace: {
        id: workspace.id,
        name: workspace.name,
        role: req.currentWorkspace.role,
      },
      currentUser,
    });
  })
);

// New task form
app.get(
  "/tasks/new",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const workspace = req.currentWorkspace.workspace;

    const membersDocs = await WorkspaceMember.find({
      workspace_id: workspace.id,
    })
      .populate("user_id")
      .sort({ "user_id.name": 1 });

    const members = membersDocs
      .filter((m) => m.user_id)
      .map((m) => ({
        id: m.user_id._id.toString(),
        name: m.user_id.name,
        role: m.role,
      }));

    res.render("new", {
      title: "Create Task",
      members,
      workspace,
    });
  })
);

// Create task
app.post(
  "/tasks",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const userId = req.session.user.id;
    const workspace = req.currentWorkspace.workspace;
    const { title, description, tag, priority, due_date, assigned_to } = req.body;

    if (!title || title.trim() === "") {
      req.session.error = "Title is required.";
      return res.redirect("/tasks/new");
    }

    let assigneeId = null;
    if (assigned_to) {
      const member = await WorkspaceMember.findOne({
        workspace_id: workspace.id,
        user_id: assigned_to,
      });
      if (member) {
        assigneeId = assigned_to;
      }
    }

    const task = await Task.create({
      workspace_id: workspace.id,
      created_by: userId,
      assigned_to: assigneeId,
      title: title.trim(),
      description: description || "",
      status: "todo",
      priority: priority || "medium",
      tag: tag || "",
      due_date: due_date ? new Date(due_date) : null,
    });

    if (assigneeId && assigneeId.toString() !== userId.toString()) {
      await createNotification(
        assigneeId,
        "assignment",
        `${req.session.user.name} assigned you a task: "${title.trim()}" in workspace "${workspace.name}".`
      );

      // 📧 EMAIL — Task assignment (on create)
      try {
        const assignedUser = await User.findById(assigneeId);
        if (assignedUser) {
          await sendEmail({
            to: assignedUser.email,
            subject: `New task assigned: ${title.trim()}`,
            message: `${req.session.user.name} assigned you a new task in workspace "${workspace.name}":\n\n"${title.trim()}"\n\nLog in to TaskBoard to see the details.`,
          });
        }
      } catch (e) {
        console.error("Task assignment email error (create):", e);
      }
    }

    req.session.success = "Task created.";
    res.redirect("/tasks");
  })
);

// Update task (status / priority / assignee)
app.post(
  "/tasks/:id/update",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const currentUser = req.session.user;
    const workspace = req.currentWorkspace.workspace;
    const taskId = req.params.id;
    const { status, priority, assigned_to } = req.body;

    const task = await Task.findOne({
      _id: taskId,
      workspace_id: workspace.id,
    });

    if (!task) {
      req.session.error = "Task not found.";
      return res.redirect("/tasks");
    }

    const oldStatus = task.status;
    const oldAssignee = task.assigned_to ? task.assigned_to.toString() : null;

    const isOwner =
      currentUser.id.toString() === workspace.created_by.toString();

    let newAssignee = oldAssignee;

    if (isOwner && typeof assigned_to !== "undefined") {
      if (assigned_to === "" || assigned_to === null) {
        newAssignee = null;
      } else {
        const member = await WorkspaceMember.findOne({
          workspace_id: workspace.id,
          user_id: assigned_to,
        });
        if (member) {
          newAssignee = assigned_to;
        }
      }
    }

    const newStatus = status || oldStatus;
    const newPriority = priority || task.priority;

    task.status = newStatus;
    task.priority = newPriority;
    task.assigned_to = newAssignee ? newAssignee : undefined;
    await task.save();

    // 1) status change -> notify owner
    if (
      newStatus !== oldStatus &&
      currentUser.id.toString() !== workspace.created_by.toString()
    ) {
      await createNotification(
        workspace.created_by,
        "task_update",
        `${currentUser.name} moved "${task.title}" to ${newStatus.toUpperCase()}.`
      );
    }

    // 2) task completed
    if (newStatus === "done" && oldStatus !== "done") {
      await createNotification(
        workspace.created_by,
        "task_done",
        `${currentUser.name} completed "${task.title}".`
      );

      // 📧 EMAIL — Notify owner task was completed
      try {
        const owner = await User.findById(workspace.created_by);
        if (owner) {
          await sendEmail({
            to: owner.email,
            subject: `Task completed: ${task.title}`,
            message: `${currentUser.name} marked the task "${task.title}" as DONE in workspace "${workspace.name}".`,
          });
        }
      } catch (e) {
        console.error("Task completion email error:", e);
      }
    }

    // 3) assignment changed by owner
    if (isOwner && newAssignee && newAssignee !== oldAssignee) {
      await createNotification(
        newAssignee,
        "assignment",
        `${currentUser.name} assigned you to "${task.title}" in "${workspace.name}".`
      );

      // 📧 EMAIL — Task reassignment
      try {
        const assignedUser = await User.findById(newAssignee);
        if (assignedUser) {
          await sendEmail({
            to: assignedUser.email,
            subject: `You were assigned to: ${task.title}`,
            message: `${currentUser.name} assigned you to the task "${task.title}" in workspace "${workspace.name}".`,
          });
        }
      } catch (e) {
        console.error("Task reassignment email error (update):", e);
      }
    }

    req.session.success = "Task updated.";
    res.redirect("/tasks");
  })
);

app.post(
  "/tasks/:id/delete",
  authRequired,
  workspaceRequired,
  asyncHandler(async (req, res) => {
    const workspace = req.currentWorkspace.workspace;
    const taskId = req.params.id;

    await Task.deleteOne({
      _id: taskId,
      workspace_id: workspace.id,
    });

    req.session.success = "Task deleted.";
    res.redirect("/tasks");
  })
);


app.get("/health", (_, res) => {
  res.status(200).json({ status: "ok" });
});


app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).send("Something went wrong.");
});



startServer();
