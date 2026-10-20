import os
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path

import jwt
from pwdlib import PasswordHash
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr, Field


# =========================
# Configuration
# =========================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "blog.db"

SECRET_KEY = os.getenv("BLOG_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "Set the BLOG_SECRET_KEY environment variable before starting the app."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

password_hash = PasswordHash.recommended()
security = HTTPBearer(auto_error=False)

app = FastAPI(title="Blog API")


# =========================
# Database
# =========================

@contextmanager
def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_tables():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)


@app.on_event("startup")
def startup():
    create_tables()


def get_time():
    return datetime.now(timezone.utc).isoformat()


# =========================
# Request Models
# =========================

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class PostCreate(BaseModel):
    title: str = Field(min_length=1, max_length=150)
    content: str = Field(min_length=1, max_length=20000)


class PostUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=150)
    content: str = Field(min_length=1, max_length=20000)


# =========================
# Authentication
# =========================

def create_access_token(user_id: int):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = int(payload["sub"])

    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with get_db() as db:
        user = db.execute(
            """
            SELECT id, username, email, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(user)


# =========================
# Helper Functions
# =========================

def get_post_or_404(post_id: int):
    with get_db() as db:
        post = db.execute(
            """
            SELECT
                posts.id,
                posts.title,
                posts.content,
                posts.user_id,
                users.username AS author,
                posts.created_at,
                posts.updated_at
            FROM posts
            JOIN users ON users.id = posts.user_id
            WHERE posts.id = ?
            """,
            (post_id,),
        ).fetchone()

    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    return dict(post)


# =========================
# Register
# =========================

@app.post("/register", status_code=201)
def register(user: UserCreate):
    username = user.username.strip()
    email = str(user.email).strip().lower()

    if len(username) < 3:
        raise HTTPException(
            status_code=422,
            detail="Username must contain at least 3 characters",
        )

    hashed_password = password_hash.hash(user.password)

    try:
        with get_db() as db:
            cursor = db.execute(
                """
                INSERT INTO users (
                    username,
                    email,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    email,
                    hashed_password,
                    get_time(),
                ),
            )

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists",
        )

    return {
        "message": "User registered successfully",
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
        },
    }


# =========================
# Login
# =========================

@app.post("/login")
def login(user: UserLogin):
    email = str(user.email).strip().lower()

    with get_db() as db:
        existing_user = db.execute(
            """
            SELECT id, username, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()

    if existing_user is None:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
        )

    try:
        valid_password = password_hash.verify(
            user.password,
            existing_user["password_hash"],
        )
    except Exception:
        valid_password = False

    if not valid_password:
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
        )

    token = create_access_token(existing_user["id"])

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": existing_user["id"],
            "username": existing_user["username"],
            "email": existing_user["email"],
        },
    }


# =========================
# Current User
# =========================

@app.get("/me")
def get_me(current_user=Depends(get_current_user)):
    return {"user": current_user}


# =========================
# Get All Posts
# =========================

@app.get("/posts")
def get_posts(
    q: str = Query(default="", max_length=150),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    with get_db() as db:
        if q.strip():
            search = f"%{q.strip()}%"

            posts = db.execute(
                """
                SELECT
                    posts.id,
                    posts.title,
                    posts.content,
                    posts.user_id,
                    users.username AS author,
                    posts.created_at,
                    posts.updated_at
                FROM posts
                JOIN users ON users.id = posts.user_id
                WHERE posts.title LIKE ?
                   OR posts.content LIKE ?
                   OR users.username LIKE ?
                ORDER BY posts.id DESC
                LIMIT ? OFFSET ?
                """,
                (search, search, search, limit, offset),
            ).fetchall()
        else:
            posts = db.execute(
                """
                SELECT
                    posts.id,
                    posts.title,
                    posts.content,
                    posts.user_id,
                    users.username AS author,
                    posts.created_at,
                    posts.updated_at
                FROM posts
                JOIN users ON users.id = posts.user_id
                ORDER BY posts.id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

    return [dict(post) for post in posts]


# =========================
# Get One Post
# =========================

@app.get("/posts/{post_id}")
def get_post(post_id: int):
    return get_post_or_404(post_id)


# =========================
# Create Post
# =========================

@app.post("/posts", status_code=201)
def create_post(
    post: PostCreate,
    current_user=Depends(get_current_user),
):
    title = post.title.strip()
    content = post.content.strip()

    if not title or not content:
        raise HTTPException(
            status_code=422,
            detail="Title and content cannot be empty",
        )

    current_time = get_time()

    with get_db() as db:
        cursor = db.execute(
            """
            INSERT INTO posts (
                title,
                content,
                user_id,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                title,
                content,
                current_user["id"],
                current_time,
                current_time,
            ),
        )

        post_id = cursor.lastrowid

    return get_post_or_404(post_id)


# =========================
# Update Post
# =========================

@app.put("/posts/{post_id}")
def update_post(
    post_id: int,
    post: PostUpdate,
    current_user=Depends(get_current_user),
):
    title = post.title.strip()
    content = post.content.strip()

    if not title or not content:
        raise HTTPException(
            status_code=422,
            detail="Title and content cannot be empty",
        )

    with get_db() as db:
        existing_post = db.execute(
            """
            SELECT id, user_id
            FROM posts
            WHERE id = ?
            """,
            (post_id,),
        ).fetchone()

        if existing_post is None:
            raise HTTPException(
                status_code=404,
                detail="Post not found",
            )

        if existing_post["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=403,
                detail="You can only update your own posts",
            )

        db.execute(
            """
            UPDATE posts
            SET title = ?, content = ?, updated_at = ?
            WHERE id = ?
            """,
            (title, content, get_time(), post_id),
        )

    return get_post_or_404(post_id)


# =========================
# Delete Post
# =========================

@app.delete("/posts/{post_id}")
def delete_post(
    post_id: int,
    current_user=Depends(get_current_user),
):
    with get_db() as db:
        existing_post = db.execute(
            """
            SELECT id, user_id
            FROM posts
            WHERE id = ?
            """,
            (post_id,),
        ).fetchone()

        if existing_post is None:
            raise HTTPException(
                status_code=404,
                detail="Post not found",
            )

        if existing_post["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=403,
                detail="You can only delete your own posts",
            )

        db.execute(
            "DELETE FROM posts WHERE id = ?",
            (post_id,),
        )

    return {"message": "Post deleted successfully"}


# ==================================================
# Frontend: HTML, CSS and JavaScript in this file
# ==================================================

HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Inkline Blog</title>

    <style>
        :root {
            --background: #f7f7f3;
            --surface: #ffffff;
            --text: #252923;
            --muted: #777b73;
            --primary: #426b50;
            --border: #e6e7df;
            --danger: #b73535;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--background);
            color: var(--text);
            font-family: Arial, Helvetica, sans-serif;
            line-height: 1.7;
        }

        button, input, textarea {
            font: inherit;
        }

        button {
            cursor: pointer;
            border: 0;
            border-radius: 9px;
            padding: 10px 16px;
            background: var(--primary);
            color: white;
            font-weight: bold;
        }

        button:disabled {
            cursor: not-allowed;
            opacity: 0.6;
        }

        button.secondary {
            background: #e9ece7;
            color: var(--text);
        }

        button.danger {
            background: var(--danger);
        }

        input, textarea {
            width: 100%;
            padding: 12px;
            border: 1px solid var(--border);
            border-radius: 9px;
            background: white;
            color: var(--text);
        }

        textarea {
            min-height: 160px;
            resize: vertical;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            padding: 18px max(20px, calc((100% - 1050px) / 2));
            background: white;
            border-bottom: 1px solid var(--border);
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
        }

        .logo span {
            color: var(--primary);
        }

        nav {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }

        main {
            width: min(1050px, calc(100% - 32px));
            margin: auto;
        }

        .hero {
            padding: 65px 0 55px;
            max-width: 680px;
        }

        .hero h1 {
            margin: 0;
            font-size: clamp(38px, 7vw, 64px);
            line-height: 1.2;
        }

        .hero h1 span {
            color: var(--primary);
        }

        .hero p {
            color: var(--muted);
            font-size: 17px;
        }

        .section-heading {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .search-form {
            display: flex;
            gap: 8px;
            margin: 20px 0;
        }

        .search-form input {
            flex: 1;
            min-width: 0;
        }

        .posts-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 16px;
        }

        .post-card {
            display: flex;
            flex-direction: column;
            min-width: 0;
            padding: 20px;
            border: 1px solid var(--border);
            border-radius: 14px;
            background: var(--surface);
        }

        .post-card h3 {
            margin: 0 0 8px;
            overflow-wrap: anywhere;
        }

        .post-excerpt {
            color: var(--muted);
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .post-meta {
            margin-top: auto;
            padding-top: 12px;
            color: var(--muted);
            font-size: 12px;
        }

        .read-more {
            align-self: flex-start;
            margin-top: 12px;
        }

        #message {
            min-height: 24px;
            color: var(--muted);
        }

        .hidden {
            display: none !important;
        }

        dialog {
            width: min(550px, calc(100% - 24px));
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            color: var(--text);
            background: white;
        }

        dialog::backdrop {
            background: #0008;
        }

        .dialog-heading {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }

        .form {
            display: grid;
            gap: 12px;
            margin-top: 18px;
        }

        .error {
            color: var(--danger);
        }

        .post-content {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 20px;
        }

        footer {
            margin-top: 70px;
            padding: 25px;
            border-top: 1px solid var(--border);
            color: var(--muted);
            text-align: center;
        }

        @media (max-width: 760px) {
            .posts-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        @media (max-width: 520px) {
            .posts-grid {
                grid-template-columns: 1fr;
            }

            header {
                align-items: flex-start;
            }

            .hero {
                padding-top: 40px;
            }
        }
    </style>
</head>

<body>
    <header>
        <div class="logo">Inkline <span>Blog</span></div>

        <nav>
            <span id="greeting"></span>
            <button id="login-button" class="secondary">Login</button>
            <button id="register-button">Register</button>
            <button id="logout-button" class="secondary hidden">Logout</button>
        </nav>
    </header>

    <main>
        <section class="hero">
            <p>YOUR SPACE FOR IDEAS</p>
            <h1>Every idea deserves <span>to be written.</span></h1>
            <p>Write your thoughts, share your experiences, and discover new stories.</p>
            <button id="hero-write-button">Write a Post</button>
        </section>

        <section>
            <div class="section-heading">
                <h2>Latest Posts</h2>
                <button id="new-post-button" class="hidden">+ New Post</button>
            </div>

            <form id="search-form" class="search-form">
                <input id="search-input" maxlength="150"
                       placeholder="Search posts or authors...">
                <button type="submit">Search</button>
            </form>

            <p id="message" role="status"></p>
            <div id="posts-grid" class="posts-grid"></div>
            <p id="empty-message" class="hidden">No posts found.</p>
            <button id="load-more-button" class="secondary hidden">
                Load More
            </button>
        </section>
    </main>

    <footer>Inkline Blog — Every story starts somewhere.</footer>

    <dialog id="auth-dialog">
        <div class="dialog-heading">
            <h2 id="auth-title">Login</h2>
            <button class="secondary" data-close="auth-dialog">Close</button>
        </div>

        <form id="auth-form" class="form">
            <input id="username-input" class="hidden"
                   placeholder="Username" minlength="3" maxlength="30">
            <input id="email-input" type="email"
                   placeholder="Email address" required>
            <input id="password-input" type="password"
                   placeholder="Password (at least 8 characters)"
                   minlength="8" maxlength="128" required>
            <p id="auth-error" class="error"></p>
            <button id="auth-submit" type="submit">Login</button>
        </form>

        <p>
            <span id="switch-text">Don't have an account?</span>
            <button id="switch-auth-button" class="secondary">
                Register
            </button>
        </p>
    </dialog>

    <dialog id="post-dialog">
        <div class="dialog-heading">
            <h2 id="post-dialog-title">New Post</h2>
            <button class="secondary" data-close="post-dialog">Close</button>
        </div>

        <form id="post-form" class="form">
            <input id="post-title" maxlength="150"
                   placeholder="Post title" required>
            <textarea id="post-content" maxlength="20000"
                      placeholder="Write your post..." required></textarea>
            <p id="post-error" class="error"></p>
            <button id="post-submit" type="submit">Publish Post</button>
        </form>
    </dialog>

    <dialog id="detail-dialog">
        <div class="dialog-heading">
            <h2>Post Details</h2>
            <button class="secondary" data-close="detail-dialog">Close</button>
        </div>

        <article id="post-detail"></article>

        <div id="post-actions" class="actions hidden">
            <button id="edit-button">Edit</button>
            <button id="delete-button" class="danger">Delete</button>
        </div>
    </dialog>

    <script>
        "use strict";

        const $ = (id) => document.getElementById(id);
        const TOKEN_KEY = "inkline_token";

        let token = localStorage.getItem(TOKEN_KEY) || "";
        let currentUser = null;
        let editingPostId = null;
        let activePost = null;
        let authMode = "login";
        let offset = 0;
        const pageSize = 9;

        async function api(url, options = {}) {
            const headers = { ...(options.headers || {}) };

            if (options.body) {
                headers["Content-Type"] = "application/json";
            }

            if (token) {
                headers["Authorization"] = "Bearer " + token;
            }

            let response;

            try {
                response = await fetch(url, { ...options, headers });
            } catch {
                throw new Error("Could not connect to the server.");
            }

            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                if (response.status === 401 && token) {
                    token = "";
                    currentUser = null;
                    localStorage.removeItem(TOKEN_KEY);
                    updateNavigation();
                }

                throw new Error(
                    typeof data.detail === "string"
                        ? data.detail
                        : "Request failed."
                );
            }

            return data;
        }

        function showMessage(message) {
            $("message").textContent = message || "";
        }

        function updateNavigation() {
            const loggedIn = Boolean(currentUser);

            $("greeting").textContent = loggedIn
                ? "Hello, " + currentUser.username
                : "";

            $("login-button").classList.toggle("hidden", loggedIn);
            $("register-button").classList.toggle("hidden", loggedIn);
            $("logout-button").classList.toggle("hidden", !loggedIn);
            $("new-post-button").classList.toggle("hidden", !loggedIn);
        }

        function openDialog(id) {
            if (!$ (id).open) {
                $(id).showModal();
            }
        }

        function closeDialog(id) {
            if ($(id).open) {
                $(id).close();
            }
        }

        document.querySelectorAll("[data-close]").forEach((button) => {
            button.addEventListener("click", () => {
                closeDialog(button.dataset.close);
            });
        });

        function openAuth(mode) {
            authMode = mode;

            $("auth-title").textContent =
                mode === "login" ? "Login" : "Create Account";

            $("auth-submit").textContent =
                mode === "login" ? "Login" : "Register";

            $("username-input").classList.toggle(
                "hidden",
                mode === "login"
            );

            $("username-input").required = mode === "register";

            $("switch-text").textContent =
                mode === "login"
                    ? "Don't have an account?"
                    : "Already have an account?";

            $("switch-auth-button").textContent =
                mode === "login" ? "Register" : "Login";

            $("auth-error").textContent = "";
            $("auth-form").reset();

            openDialog("auth-dialog");
        }

        $("login-button").onclick = () => openAuth("login");
        $("register-button").onclick = () => openAuth("register");

        $("switch-auth-button").onclick = () => {
            openAuth(authMode === "login" ? "register" : "login");
        };

        $("logout-button").onclick = () => {
            token = "";
            currentUser = null;

            localStorage.removeItem(TOKEN_KEY);
            updateNavigation();
            showMessage("Logged out successfully.");
        };

        $("auth-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            $("auth-error").textContent = "";

            const email = $("email-input").value.trim().toLowerCase();
            const password = $("password-input").value;

            const payload = { email, password };

            if (authMode === "register") {
                payload.username = $("username-input").value.trim();
            }

            try {
                if (authMode === "register") {
                    await api("/register", {
                        method: "POST",
                        body: JSON.stringify(payload),
                    });
                }

                const result = await api("/login", {
                    method: "POST",
                    body: JSON.stringify({ email, password }),
                });

                token = result.access_token;
                currentUser = result.user;

                localStorage.setItem(TOKEN_KEY, token);
                updateNavigation();
                closeDialog("auth-dialog");

                showMessage("Login successful.");
                await loadPosts(true);
            } catch (error) {
                $("auth-error").textContent = error.message;
            }
        });

        async function restoreSession() {
            if (!token) {
                updateNavigation();
                return;
            }

            try {
                const result = await api("/me");
                currentUser = result.user;
            } catch {
                token = "";
                currentUser = null;
                localStorage.removeItem(TOKEN_KEY);
            }

            updateNavigation();
        }

        function createElement(tag, className, text) {
            const element = document.createElement(tag);

            if (className) {
                element.className = className;
            }

            if (text !== undefined) {
                element.textContent = text;
            }

            return element;
        }

        function formatDate(value) {
            const date = new Date(value);

            if (Number.isNaN(date.getTime())) {
                return "";
            }

            return date.toLocaleDateString("en-US", {
                year: "numeric",
                month: "short",
                day: "numeric",
            });
        }

        function renderPost(post) {
            const card = createElement("article", "post-card");
            const title = createElement("h3", "", post.title);
            const content = createElement(
                "p",
                "post-excerpt",
                post.content.length > 180
                    ? post.content.slice(0, 180) + "..."
                    : post.content
            );

            const meta = createElement(
                "p",
                "post-meta",
                "By " + post.author + " · " + formatDate(post.created_at)
            );

            const readButton = createElement(
                "button",
                "read-more",
                "Read Post"
            );

            readButton.onclick = () => openPost(post.id);

            card.append(title, content, meta, readButton);
            $("posts-grid").appendChild(card);
        }

        async function loadPosts(reset = false) {
            if (reset) {
                offset = 0;
                $("posts-grid").replaceChildren();
            }

            showMessage("Loading posts...");
            $("load-more-button").disabled = true;

            try {
                const params = new URLSearchParams({
                    q: $("search-input").value.trim(),
                    limit: String(pageSize),
                    offset: String(offset),
                });

                const posts = await api("/posts?"  + params.toString());

                posts.forEach(renderPost);
                offset += posts.length;

                $("empty-message").classList.toggle(
                    "hidden",
                    $("posts-grid").children.length > 0
                );

                $("load-more-button").classList.toggle(
                    "hidden",
                    posts.length < pageSize
                );

                showMessage(
                    posts.length ? "" : "No more posts to display."
                );
            } catch (error) {
                showMessage(error.message);
            } finally {
                $("load-more-button").disabled = false;
            }
        }

        $("search-form").addEventListener("submit", (event) => {
            event.preventDefault();
            loadPosts(true);
        });

        $("load-more-button").onclick = () => loadPosts(false);

        async function openPost(postId) {
            try {
                const post = await api("/posts/" + postId);
                activePost = post;

                $("post-detail").replaceChildren();

                const title = createElement("h2", "", post.title);
                const meta = createElement(
                    "p",
                    "post-meta",
                    "By " + post.author + " · " + formatDate(post.created_at)
                );
                const content = createElement(
                    "p",
                    "post-content",
                    post.content
                );

                $("post-detail").append(title, meta, content);

                const isOwner = Boolean(
                    currentUser && currentUser.id === post.user_id
                );

                $("post-actions").classList.toggle("hidden", !isOwner);
                openDialog("detail-dialog");
            } catch (error) {
                showMessage(error.message);
            }
        }

        function openPostForm(post = null) {
            if (!currentUser) {
                openAuth("login");
                return;
            }

            editingPostId = post ? post.id : null;

            $("post-form").reset();
            $("post-error").textContent = "";

            $("post-dialog-title").textContent =
                post ? "Edit Post" : "New Post";

            $("post-submit").textContent =
                post ? "Save Changes" : "Publish Post";

            if (post) {
                $("post-title").value = post.title;
                $("post-content").value = post.content;
            }

            openDialog("post-dialog");
        }

        $("hero-write-button").onclick = () => openPostForm();
        $("new-post-button").onclick = () => openPostForm();

        $("edit-button").onclick = () => {
            if (!activePost) {
                return;
            }

            closeDialog("detail-dialog");
            openPostForm(activePost);
        };

        $("post-form").addEventListener("submit", async (event) => {
            event.preventDefault();
            $("post-error").textContent = "";

            const payload = {
                title: $("post-title").value.trim(),
                content: $("post-content").value.trim(),
            };

            try {
                const editing = editingPostId !== null;

                await api(
                    editing ? "/posts/" + editingPostId : "/posts",
                    {
                        method: editing ? "PUT" : "POST",
                        body: JSON.stringify(payload),
                    }
                );

                closeDialog("post-dialog");
                closeDialog("detail-dialog");

                showMessage(
                    editing
                        ? "Post updated successfully."
                        : "Post published successfully."
                );

                editingPostId = null;
                $("search-input").value = "";

                await loadPosts(true);
            } catch (error) {
                $("post-error").textContent = error.message;
            }
        });

        $("delete-button").onclick = async () => {
            if (!activePost) {
                return;
            }

            if (!confirm("Are you sure you want to delete this post?")) {
                return;
            }

            try {
                await api("/posts/" + activePost.id, {
                    method: "DELETE",
                });

                closeDialog("detail-dialog");
                activePost = null;

                showMessage("Post deleted successfully.");
                await loadPosts(true);
            } catch (error) {
                showMessage(error.message);
            }
        };

        async function startApp() {
            await restoreSession();
            await loadPosts(true);
        }

        startApp();
    </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return HTML_PAGE


@app.get("/health")
def health_check():
    return {"status": "ok"}


# Run using:
# uvicorn main:app --reload