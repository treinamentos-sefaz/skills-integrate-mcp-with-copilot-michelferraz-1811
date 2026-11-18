"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import hashlib
import hmac
import json
import secrets
import time
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

SESSION_COOKIE_NAME = "teacher_session"
SESSION_LIFETIME_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000
CREDENTIALS_FILE = current_dir / "teacher_credentials.json"


def load_teacher_credentials() -> dict[str, dict[str, str]]:
    try:
        config = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Unable to load teacher credentials from {CREDENTIALS_FILE}"
        ) from error

    teachers = config.get("teachers") if isinstance(config, dict) else None
    if not isinstance(teachers, dict):
        raise RuntimeError("Teacher credentials must contain a 'teachers' object")

    for username, credential in teachers.items():
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(credential, dict)
            or not isinstance(credential.get("salt"), str)
            or not isinstance(credential.get("password_hash"), str)
        ):
            raise RuntimeError("Each teacher must have a salt and password_hash")
        try:
            salt = bytes.fromhex(credential["salt"])
            password_hash = bytes.fromhex(credential["password_hash"])
        except ValueError as error:
            raise RuntimeError(f"Invalid credential encoding for {username}") from error
        if len(salt) < 16 or len(password_hash) != 32:
            raise RuntimeError(f"Invalid credential lengths for {username}")

    return teachers


teacher_credentials = load_teacher_credentials()
sessions: dict[str, tuple[str, float]] = {}


class LoginRequest(BaseModel):
    username: Annotated[str, Field(min_length=1, max_length=100)]
    password: Annotated[str, Field(min_length=1, max_length=1024)]


def verify_teacher_password(username: str, password: str) -> bool:
    credential = teacher_credentials.get(username)
    salt = bytes.fromhex(credential["salt"]) if credential else bytes(16)
    expected_hash = (
        bytes.fromhex(credential["password_hash"]) if credential else bytes(32)
    )
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return credential is not None and hmac.compare_digest(actual_hash, expected_hash)


def get_authenticated_teacher(session_id: str | None) -> str | None:
    if session_id is None:
        return None
    session = sessions.get(session_id)
    if session is None:
        return None
    username, expires_at = session
    if expires_at <= time.time():
        sessions.pop(session_id, None)
        return None
    return username


def require_teacher(
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> str:
    username = get_authenticated_teacher(session_id)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.get("/auth/session")
def get_session(
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    username = get_authenticated_teacher(session_id)
    return {"authenticated": username is not None, "username": username}


@app.post("/auth/login")
def login(
    credentials: LoginRequest, request: Request, response: Response
):
    if not verify_teacher_password(credentials.username, credentials.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    now = time.time()
    for session_id, (_, expires_at) in list(sessions.items()):
        if expires_at <= now:
            sessions.pop(session_id, None)

    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = (
        credentials.username,
        now + SESSION_LIFETIME_SECONDS,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return {"message": "Logged in", "username": credentials.username}


@app.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    session_id: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
):
    if session_id is not None:
        sessions.pop(session_id, None)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )
    return {"message": "Logged out"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, email: str, _: Annotated[str, Depends(require_teacher)]
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, _: Annotated[str, Depends(require_teacher)]
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
