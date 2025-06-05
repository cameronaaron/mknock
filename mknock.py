import os
import asyncio
import logging
import httpx
import random
import time
import json
import re
from contextlib import asynccontextmanager
from collections import deque

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
import uvicorn

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configuration from environment variables
logger.debug("Reading environment variables for configuration...")

BEEPER_API_BASE = os.environ.get("BEEPER_API_BASE", "https://api.beeper.com")
MATRIX_BASE_URL = os.environ.get("MATRIX_BASE_URL", "https://matrix.beeper.com")
NEW_ROOM_ID = os.environ.get("NEW_ROOM_ID", "")

# Security configuration
API_KEY = os.environ.get("API_KEY")  # Set this environment variable for security
if not API_KEY:
    logger.warning("API_KEY environment variable not set! Endpoints will be unsecured!")

# Rate limiting configuration
REQUEST_DELAY = float(os.environ.get("REQUEST_DELAY", "0.5"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "5"))
BASE_BACKOFF_DELAY = float(os.environ.get("BASE_BACKOFF_DELAY", "2.0"))

# File paths for persistent storage
TOKENS_FILE = os.environ.get("TOKENS_FILE", "tokens.json")
BLOCKLIST_FILE = os.environ.get("BLOCKLIST_FILE", "blocked_users.txt")
PENDING_INVITES_FILE = os.environ.get("PENDING_INVITES_FILE", "pending_invites.json")

# Beeper login credentials
BEEPER_LOGIN_EMAIL = os.environ.get("BEEPER_LOGIN_EMAIL")
BEEPER_LOGIN_CODE = os.environ.get("BEEPER_LOGIN_CODE")
BEEPER_LOGIN_TOKEN_ENV = os.environ.get("BEEPER_LOGIN_TOKEN")
MATRIX_ACCESS_TOKEN_ENV = os.environ.get("MATRIX_ACCESS_TOKEN")

logger.debug("Done reading environment variables.")

# Global token storage
BEEPER_LOGIN_TOKEN = None
MATRIX_ACCESS_TOKEN = None

# Initialize data structures
logger.debug("Initializing in-memory structures...")

# Spam protection
RECENT_REQUESTS = deque()
SPAM_WINDOW_SECONDS = 60
MAX_REQUESTS_PER_WINDOW = 10

# Persistent storage dictionaries
PENDING_INVITES = {}
BLOCKLIST = {}

# Concurrency locks
BLOCKLIST_LOCK = asyncio.Lock()
PENDING_INVITES_LOCK = asyncio.Lock()

logger.debug("Done initializing.")

# Utility functions for fuzzy matching
def normalize_matrix_id(user_id: str) -> str:
    """Convert user_id to canonical lowercase form with leading '@'."""
    user_id = user_id.strip().lower()
    if not user_id.startswith("@"):
        user_id = "@" + user_id
    return user_id

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    rows = len(s1) + 1
    cols = len(s2) + 1
    dist = [[0] * cols for _ in range(rows)]

    for i in range(1, rows):
        dist[i][0] = i
    for j in range(1, cols):
        dist[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dist[i][j] = min(
                dist[i - 1][j] + 1,        # deletion
                dist[i][j - 1] + 1,        # insertion
                dist[i - 1][j - 1] + cost  # substitution
            )

    return dist[-1][-1]

def fuzzy_match(user_id: str, blocked_id: str, max_distance: int = 2) -> bool:
    """Check if user_id is similar enough to blocked_id to be considered a ban-evading variant."""
    if user_id == blocked_id:
        return True
    user_id = user_id.strip().lower()
    blocked_id = blocked_id.strip().lower()

    # Split into localpart and domain
    user_parts = user_id.split(':', 1)
    blocked_parts = blocked_id.split(':', 1)
    if len(user_parts) != 2 or len(blocked_parts) != 2:
        # Fallback to simple Levenshtein for non-standard matrix IDs
        distance = levenshtein_distance(user_id, blocked_id)
        return distance <= max_distance

    user_localpart = user_parts[0].lstrip('@')
    user_domain = user_parts[1]
    blocked_localpart = blocked_parts[0].lstrip('@')
    blocked_domain = blocked_parts[1]

    # Domain must match exactly
    if user_domain != blocked_domain:
        return False

    # Exact localpart match
    if user_localpart == blocked_localpart:
        return True

    # Levenshtein distance check on localpart
    localpart_distance = levenshtein_distance(user_localpart, blocked_localpart)
    if localpart_distance <= max_distance:
        return True

    # Check for numeric suffix variations
    user_base = re.sub(r'\d+$', '', user_localpart)
    blocked_base = re.sub(r'\d+$', '', blocked_localpart)
    if user_base == blocked_base:
        return True

    # Character substitution patterns (leet speak, etc.)
    substitution_patterns = [
        (r'0', 'o'), (r'1', 'l'), (r'3', 'e'), (r'4', 'a'),
        (r'5', 's'), (r'6', 'b'), (r'7', 't'), (r'8', 'b'),
    ]
    normalized_user = user_localpart
    normalized_blocked = blocked_localpart
    for pattern, replacement in substitution_patterns:
        normalized_user = re.sub(pattern, replacement, normalized_user)
        normalized_blocked = re.sub(pattern, replacement, normalized_blocked)

    if levenshtein_distance(normalized_user, normalized_blocked) <= max_distance:
        return True

    return False

async def is_user_blocked(user_id: str) -> bool:
    """Check if user is blocked (exact or fuzzy match)."""
    normalized = normalize_matrix_id(user_id)
    async with BLOCKLIST_LOCK:
        # Exact match check
        if normalized in BLOCKLIST:
            logger.debug(f"User {normalized} is explicitly in BLOCKLIST.")
            return True
        # Fuzzy match check
        for blocked_id in BLOCKLIST:
            if fuzzy_match(normalized, blocked_id):
                logger.debug(f"User {normalized} fuzzy-matched to {blocked_id} in BLOCKLIST.")
                return True
    return False

async def get_block_reason_if_blocked(user_id: str) -> str:
    """Return the block reason if user is blocked, empty string otherwise."""
    normalized = normalize_matrix_id(user_id)
    async with BLOCKLIST_LOCK:
        if normalized in BLOCKLIST:
            return BLOCKLIST[normalized]
        for blocked_id, reason in BLOCKLIST.items():
            if fuzzy_match(normalized, blocked_id):
                return reason
    return ""

# Blocklist file operations
def parse_blocklist_line(line: str) -> (str, str):
    line = line.strip()
    if not line:
        return "", ""
    match = re.match(r"^(?P<user>[^ ]+)(?:\s+Reason:\s+(?P<reason>.*))?$", line)
    if match:
        user_part = match.group("user")
        reason_part = match.group("reason")
        if not reason_part:
            reason_part = "No reason provided"
        return normalize_matrix_id(user_part), reason_part.strip()
    # Fallback
    return normalize_matrix_id(line), "No reason provided"

def load_blocklist_from_file():
    logger.debug("Attempting to load blocklist from file...")
    global BLOCKLIST
    if not os.path.exists(BLOCKLIST_FILE):
        logger.info(f"No blocklist file found ({BLOCKLIST_FILE}), creating empty.")
        try:
            directory = os.path.dirname(BLOCKLIST_FILE)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            with open(BLOCKLIST_FILE, "w", encoding="utf-8") as _:
                pass
        except Exception as e:
            logger.error(f"Error creating blocklist file: {e}")
        return

    try:
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        new_blocklist = {}
        for line in lines:
            line = line.strip()
            if line:
                user_id, reason = parse_blocklist_line(line)
                if user_id:
                    new_blocklist[user_id] = reason
        BLOCKLIST = new_blocklist
        logger.info(f"Loaded {len(BLOCKLIST)} entries from blocklist.")
    except Exception as e:
        logger.error(f"Error reading blocklist: {e}")

def save_blocklist_to_file():
    logger.debug("Saving blocklist to file...")
    try:
        with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
            for user_id, reason in BLOCKLIST.items():
                if reason and reason != "No reason provided":
                    f.write(f"{user_id} Reason: {reason}\n")
                else:
                    f.write(f"{user_id}\n")
        logger.info("Blocklist successfully saved.")
    except Exception as e:
        logger.error(f"Error: {e}")

async def add_user_to_blocklist(user_id: str, reason: str = ""):
    normalized = normalize_matrix_id(user_id)
    async with BLOCKLIST_LOCK:
        if normalized in BLOCKLIST:
            logger.info(f"{normalized} is already in blocklist.")
            return
        BLOCKLIST[normalized] = reason if reason.strip() else "No reason provided"
        save_blocklist_to_file()
        logger.info(f"{normalized} => '{reason}' added to blocklist.")

async def remove_user_from_blocklist(user_id: str):
    normalized = normalize_matrix_id(user_id)
    async with BLOCKLIST_LOCK:
        if normalized not in BLOCKLIST:
            logger.info(f"{normalized} not in blocklist.")
            return
        BLOCKLIST.pop(normalized, None)
        save_blocklist_to_file()
        logger.info(f"Removed {normalized} from blocklist.")

# Pending invites file operations
def load_pending_invites_from_file():
    """Load pending invites from JSON file."""
    logger.debug("Attempting to load pending invites...")
    global PENDING_INVITES
    if not os.path.exists(PENDING_INVITES_FILE):
        logger.info(f"No pending invites file found ({PENDING_INVITES_FILE}), creating empty.")
        try:
            directory = os.path.dirname(PENDING_INVITES_FILE)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
            with open(PENDING_INVITES_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f)
        except Exception as e:
            logger.error(f"Error creating pending invites file: {e}")
        return

    try:
        with open(PENDING_INVITES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            PENDING_INVITES = data
            logger.info(f"Loaded {len(PENDING_INVITES)} pending invites from file.")
        else:
            logger.warning("Content is not a dict, ignoring.")
    except Exception as e:
        logger.error(f"Error loading pending invites: {e}")

def save_pending_invites_to_file():
    """Save PENDING_INVITES dict as JSON."""
    logger.debug("Saving pending invites to file...")
    try:
        with open(PENDING_INVITES_FILE, "w", encoding="utf-8") as f:
            json.dump(PENDING_INVITES, f, indent=2)
        logger.info("Saved pending invites successfully.")
    except Exception as e:
        logger.error(f"Error saving pending invites: {e}")

# Rate limiting and retry logic
async def with_rate_limit(coro, *args, **kwargs):
    """Execute coroutine with rate limiting and retry logic for 429 and network errors."""
    retries = 0
    while True:
        try:
            logger.debug(f"Sleeping {REQUEST_DELAY}s before making request (attempt {retries+1}).")
            await asyncio.sleep(REQUEST_DELAY)
            return await coro(*args, **kwargs)

        except httpx.HTTPStatusError as exc:
            logger.error(f"HTTPStatusError caught: {exc}. Response status: {exc.response.status_code}")
            if exc.response.status_code == 429:
                logger.warning("Got 429 rate limit from the server.")
                if retries < MAX_RETRIES:
                    delay = parse_retry_after_or_exponential(exc.response, retries)
                    logger.warning(f"Retrying after {delay:.2f}s (attempt {retries+1}/{MAX_RETRIES})...")
                    await asyncio.sleep(delay)
                    retries += 1
                else:
                    delay = parse_retry_after_or_exponential(exc.response, retries) * 2
                    logger.error("Exceeded max retries, but continuing anyway.")
                    await asyncio.sleep(delay)
            else:
                logger.error(f"Non-429 HTTP error, giving up: {exc}")
                raise

        except (httpx.ConnectTimeout, httpx.ReadTimeout) as e:
            logger.warning(f"Network/Read timeout: {e}")
            if retries < MAX_RETRIES:
                delay = get_exponential_backoff(retries)
                logger.warning(f"Retrying after {delay:.2f}s (attempt {retries+1}/{MAX_RETRIES})...")
                await asyncio.sleep(delay)
                retries += 1
            else:
                delay = get_exponential_backoff(retries) * 2
                logger.error("Timeout persists, continuing anyway with extended delay.")
                await asyncio.sleep(delay)

        except httpx.RequestError as e:
            logger.error(f"Request error: {e}", exc_info=True)
            if retries < MAX_RETRIES:
                delay = get_exponential_backoff(retries)
                logger.warning(f"Retrying after {delay:.2f}s (attempt {retries+1}/{MAX_RETRIES})...")
                await asyncio.sleep(delay)
                retries += 1
            else:
                delay = get_exponential_backoff(retries) * 2
                logger.error("Request failing repeatedly, continuing with extended delay anyway.")
                await asyncio.sleep(delay)

        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            raise

def parse_retry_after_or_exponential(response: httpx.Response, retries: int) -> float:
    retry_after = response.headers.get("Retry-After")
    if retry_after and retry_after.isdigit():
        logger.debug(f"Found Retry-After header with value={retry_after}")
        return float(retry_after)
    return get_exponential_backoff(retries)

def get_exponential_backoff(retries: int) -> float:
    backoff = BASE_BACKOFF_DELAY * (2 ** retries) + (random.random() * 2)
    logger.debug(f"Calculated backoff={backoff:.2f}s for retry attempt {retries+1}")
    return backoff

# Token management
def load_tokens():
    logger.debug("Checking for existing tokens in file.")
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, 'r') as f:
                data = json.load(f)
            logger.debug("Found tokens in file.")
            return data.get("beeper_token"), data.get("matrix_token")
        except Exception as e:
            logger.error(f"Error loading tokens: {e}")
    else:
        logger.debug("Tokens file does not exist.")
    return None, None

def save_tokens(beeper_token, matrix_token):
    logger.debug("Saving beeper_token and matrix_token to file.")
    try:
        data = {"beeper_token": beeper_token, "matrix_token": matrix_token}
        with open(TOKENS_FILE, 'w') as f:
            json.dump(data, f)
        logger.info("Successfully saved tokens.")
    except Exception as e:
        logger.error(f"Error saving tokens: {e}")

# Beeper authentication flow
async def beeper_start_login(client: httpx.AsyncClient) -> dict:
    url = f"{BEEPER_API_BASE}/user/login"
    headers = {
        "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
        "Content-Type": "application/json",
    }
    async def make_request():
        r = await client.post(url, headers=headers, json={})
        r.raise_for_status()
        return r.json()
    logger.debug("Starting login with empty payload to get request_id.")
    return await with_rate_limit(make_request)

async def beeper_send_login_email(client: httpx.AsyncClient, request_id: str, email: str):
    url = f"{BEEPER_API_BASE}/user/login/email"
    headers = {
        "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
        "Content-Type": "application/json",
    }
    data = {"request": request_id, "email": email}
    async def make_request():
        r = await client.post(url, headers=headers, json=data)
        r.raise_for_status()
    logger.debug(f"Sending login email to {email} with request_id={request_id}.")
    await with_rate_limit(make_request)

async def beeper_send_login_code(client: httpx.AsyncClient, request_id: str, code: str) -> dict:
    url = f"{BEEPER_API_BASE}/user/login/response"
    headers = {
        "Authorization": "Bearer BEEPER-PRIVATE-API-PLEASE-DONT-USE",
        "Content-Type": "application/json",
    }
    data = {"request": request_id, "response": code}
    async def make_request():
        r = await client.post(url, headers=headers, json=data)
        r.raise_for_status()
        return r.json()
    logger.debug(f"Submitting 6-digit code for request_id={request_id}.")
    return await with_rate_limit(make_request)

async def matrix_login_jwt(client: httpx.AsyncClient, jwt_token: str) -> str:
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/login"
    data = {
        "type": "org.matrix.login.jwt",
        "token": jwt_token
    }
    async def make_request():
        r = await client.post(url, json=data)
        r.raise_for_status()
        return r.json()["access_token"]
    logger.debug("Exchanging beeper JWT for Matrix access token.")
    return await with_rate_limit(make_request)

# Matrix room operations
async def invite_user(client: httpx.AsyncClient, user_id: str, access_token: str) -> bool:
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/invite"
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"user_id": user_id}

    logger.info(f"Attempting to invite user: {user_id}")

    async def make_request():
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r
    
    try:
        start_time = time.time()
        response = await with_rate_limit(make_request)
        duration = time.time() - start_time
        logger.info(f"Invite for {user_id} succeeded in {duration:.2f}s, server response={response.text}")
        return True
    except httpx.HTTPStatusError as exc:
        sc = exc.response.status_code
        text = exc.response.text
        logger.error(f"HTTP error {sc} inviting {user_id}: {text}")
        if sc in (400, 403) and "already in the room" in text.lower():
            logger.info(f"{user_id} is already in the room, treating as success.")
            return True
        elif sc == 429:
            logger.warning("Rate limited, will return False so we can try again later.")
            return False
        else:
            logger.error(f"Permanent error inviting {user_id}, response text={text}")
            return False
    except Exception as e:
        logger.error(f"Unexpected error inviting {user_id}: {e}", exc_info=True)
        return False

async def check_user_in_room(client: httpx.AsyncClient, user_id: str, access_token: str) -> bool:
    """Check if a user is in the room by calling joined_members."""
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/joined_members"
    headers = {"Authorization": f"Bearer {access_token}"}

    async def make_request():
        logger.debug("Fetching joined_members to see if user is present.")
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()

    try:
        data = await with_rate_limit(make_request)
        joined = data.get("joined", {})
        in_room = user_id in joined
        logger.debug(f"user_id={user_id} is_in_room={in_room}, total_joined={len(joined)}")
        return in_room
    except httpx.HTTPStatusError as exc:
        sc = exc.response.status_code
        text = exc.response.text
        logger.error(f"HTTP error {sc} checking membership: {text}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise

async def kick_user(client: httpx.AsyncClient, user_id: str, access_token: str, reason: str = "Blocked or rescinded"):
    """Kick (or uninvite) a user from the room."""
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/kick"
    headers = {"Authorization": f"Bearer {access_token}"}
    payload = {"user_id": user_id, "reason": reason}

    async def make_request():
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r
    
    try:
        response = await with_rate_limit(make_request)
        logger.info(f"Kicked {user_id} with reason='{reason}', response={response.text}")
    except httpx.HTTPStatusError as exc:
        logger.error(f"HTTP error {exc.response.status_code}: {exc.response.text}")
    except Exception as e:
        logger.error(f"Unexpected error kicking {user_id}: {e}", exc_info=True)

async def check_room_state(client: httpx.AsyncClient, access_token: str) -> dict:
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/state"
    headers = {"Authorization": f"Bearer {access_token}"}

    async def make_request():
        logger.debug("Fetching full room state.")
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()

    try:
        data = await with_rate_limit(make_request)
        room_name = None
        room_topic = None
        canonical_alias = None
        for event in data:
            if event.get("type") == "m.room.name":
                room_name = event.get("content", {}).get("name")
            elif event.get("type") == "m.room.topic":
                room_topic = event.get("content", {}).get("topic")
            elif event.get("type") == "m.room.canonical_alias":
                canonical_alias = event.get("content", {}).get("alias")

        return {
            "name": room_name,
            "topic": room_topic,
            "canonical_alias": canonical_alias,
            "raw_state": data
        }
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        raise

async def send_welcome_message(client: httpx.AsyncClient, user_id: str, access_token: str, room_id: str = None) -> bool:
    """Send a welcome message to a user who just joined, with an HTML mention."""
    target_room = room_id or NEW_ROOM_ID
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{target_room}/send/m.room.message"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    welcome_text = f"Welcome to the room, {user_id}! 👋"
    formatted_text = (
        f"Welcome to the room, "
        f'<a href="https://matrix.to/#/{user_id}" data-mxid="{user_id}">{user_id}</a>'
        f"! 👋"
    )
    payload = {
        "msgtype": "m.text",
        "body": welcome_text,
        "format": "org.matrix.custom.html",
        "formatted_body": formatted_text
    }

    async def make_request():
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r

    try:
        await with_rate_limit(make_request)
        logger.info(f"Sent welcome message to {user_id}")
        return True
    except Exception as e:
        logger.error(f"Error sending welcome to {user_id}: {e}", exc_info=True)
        return False

# Token validation
async def ensure_matrix_token_valid(client: httpx.AsyncClient):
    """Ensure MATRIX_ACCESS_TOKEN is valid. If not, redo the beeper login flow."""
    global MATRIX_ACCESS_TOKEN
    if not MATRIX_ACCESS_TOKEN:
        logger.debug("No existing MATRIX_ACCESS_TOKEN, calling login flow.")
        await beeper_login_once(client)
        return

    ok = await test_matrix_token(client, MATRIX_ACCESS_TOKEN)
    if not ok:
        logger.warning("Matrix token invalid or expired, redoing login.")
        MATRIX_ACCESS_TOKEN = None
        await beeper_login_once(client)

async def test_matrix_token(client: httpx.AsyncClient, access_token: str) -> bool:
    """Check if the current matrix token is valid by calling whoami."""
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/account/whoami"
    headers = {"Authorization": f"Bearer {access_token}"}

    async def make_request():
        return await client.get(url, headers=headers)
    try:
        resp = await with_rate_limit(make_request)
        if resp.status_code == 401:
            logger.debug("401 => token invalid.")
            return False
        resp.raise_for_status()
        data = resp.json()
        if data.get("errcode") == "M_UNKNOWN_TOKEN":
            logger.debug("M_UNKNOWN_TOKEN => invalid.")
            return False
        logger.debug("Token is valid.")
        return True
    except httpx.HTTPStatusError as exc:
        logger.error(f"HTTP error {exc.response.status_code}, treating as invalid.")
        return False
    except Exception as e:
        logger.warning(f"Unexpected error while validating token: {e}")
        return False

# Authentication flow
async def beeper_login_once(client: httpx.AsyncClient):
    global BEEPER_LOGIN_TOKEN, MATRIX_ACCESS_TOKEN
    if BEEPER_LOGIN_TOKEN and MATRIX_ACCESS_TOKEN:
        logger.debug("Already have tokens, skipping login.")
        return
    
    logger.debug("Starting beeper login flow from scratch...")
    email = BEEPER_LOGIN_EMAIL or input("Enter Beeper email: ")
    start_data = await beeper_start_login(client)
    request_id = start_data["request"]
    await beeper_send_login_email(client, request_id, email)
    code = BEEPER_LOGIN_CODE or input("Enter 6-digit code: ")
    code_data = await beeper_send_login_code(client, request_id, code)
    BEEPER_LOGIN_TOKEN = code_data["token"]
    
    logger.debug("Got Beeper token, exchanging for Matrix token...")
    MATRIX_ACCESS_TOKEN = await matrix_login_jwt(client, BEEPER_LOGIN_TOKEN)
    logger.info("Matrix access token acquired successfully.")
    save_tokens(BEEPER_LOGIN_TOKEN, MATRIX_ACCESS_TOKEN)

# Authentication setup
security = HTTPBearer(auto_error=False)

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify the API key from the Authorization header"""
    if not API_KEY:
        # If no API key is configured, allow access (for backward compatibility)
        logger.warning("No API key configured - endpoint is unsecured!")
        return True
    
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return True

# Application lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.debug("Creating httpx client and setting up app state.")
    app.state.httpx_client = httpx.AsyncClient(timeout=15.0)
    restore_tokens_from_storage()

    logger.debug("Loading blocklist from file at startup.")
    async with BLOCKLIST_LOCK:
        load_blocklist_from_file()

    logger.debug("Loading pending invites from file at startup.")
    async with PENDING_INVITES_LOCK:
        load_pending_invites_from_file()

    logger.debug("Validating or obtaining Matrix token at startup.")
    await ensure_matrix_token_valid(app.state.httpx_client)

    logger.debug("Launching background tasks.")
    background_tasks = set()

    # Periodically check pending invites
    task_invites = asyncio.create_task(periodic_invite_checker(app))
    background_tasks.add(task_invites)
    task_invites.add_done_callback(background_tasks.discard)

    # Periodically scan all room members for blocklist violations
    task_block_scan = asyncio.create_task(periodic_member_blocklist_checker(app))
    background_tasks.add(task_block_scan)
    task_block_scan.add_done_callback(background_tasks.discard)

    yield

    # On shutdown, cancel tasks
    logger.info("Shutting down, cancelling background tasks.")
    for t in background_tasks:
        t.cancel()

    logger.info("Closing http client.")
    await app.state.httpx_client.aclose()

def restore_tokens_from_storage():
    """Load tokens from environment or from file."""
    global BEEPER_LOGIN_TOKEN, MATRIX_ACCESS_TOKEN
    logger.debug("Checking environment for tokens first.")
    if BEEPER_LOGIN_TOKEN_ENV and MATRIX_ACCESS_TOKEN_ENV:
        logger.info("Using tokens from environment variables.")
        BEEPER_LOGIN_TOKEN = BEEPER_LOGIN_TOKEN_ENV
        MATRIX_ACCESS_TOKEN = MATRIX_ACCESS_TOKEN_ENV
        return
    logger.debug("Environment tokens not found, checking token file next.")
    btoken, mtoken = load_tokens()
    if btoken and mtoken:
        logger.info("Found tokens in file.")
        BEEPER_LOGIN_TOKEN = btoken
        MATRIX_ACCESS_TOKEN = mtoken
    else:
        logger.info("No tokens found in environment or file, will do login flow later.")

# FastAPI application setup
app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    # Keep this endpoint public for health checks
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    return JSONResponse({
        "status": "running",
        "time": current_time,
        "target_room": NEW_ROOM_ID,
        "pending_invites_count": len(PENDING_INVITES),
        "api_key_configured": bool(API_KEY)
    })

def fix_common_mxid_mistakes(user_input: str) -> str:
    """
    Transform common Matrix ID mistakes like "@James.gill@beeper.com" 
    into valid format "@James.gill:beeper.com".
    """
    user_input = user_input.strip()
    user_input = re.sub(r'\s+', '', user_input)  # Remove all whitespace
    if not user_input:
        return user_input

    # Fix multiple '@' characters with no colon
    if user_input.count('@') > 1 and ':' not in user_input:
        parts = user_input.split('@', 2)
        if len(parts) == 3:
            user_input = '@' + parts[1] + ':' + parts[2]

    if not user_input.startswith('@'):
        user_input = '@' + user_input

    if ':' not in user_input:
        user_input += ":beeper.com"

    user_input = user_input.lower()
    return user_input

# User existence validation
async def user_exists(client: httpx.AsyncClient, access_token: str, user_id: str) -> bool:
    """Check if user exists on the Matrix server by fetching their profile."""
    encoded_user_id = user_id.replace(':', '%3A').replace('@', '%40')
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/profile/{encoded_user_id}"
    headers = {"Authorization": f"Bearer {access_token}"}

    async def make_request():
        return await client.get(url, headers=headers)

    try:
        resp = await with_rate_limit(make_request)
        if resp.status_code == 200:
            logger.debug(f"Confirmed user exists: {user_id}")
            return True
        if resp.status_code == 404:
            logger.debug(f"404 => user not found: {user_id}")
            return False
        resp.raise_for_status()
        return True
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            logger.debug(f"404 => user not found: {user_id}")
            return False
        logger.error(f"Error checking existence of {user_id}: {exc.response.text}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking existence of {user_id}: {e}")
        return False

@app.post("/invite_from_form")
async def invite_from_form(payload: dict, request: Request, _: bool = Depends(verify_api_key)):
    """Handle Tally-like webhook form responses for Matrix invites."""
    logger.info("Received invite request from form.")
    try:
        async with BLOCKLIST_LOCK:
            load_blocklist_from_file()

        if payload.get("eventType") != "FORM_RESPONSE":
            return JSONResponse({"error": "Invalid eventType"}, status_code=400)

        data = payload.get("data", {})
        fields = data.get("fields", [])
        if not isinstance(fields, list):
            return JSONResponse({"error": "Invalid payload"}, status_code=400)

        # Honeypot spam detection
        for f in fields:
            label = f.get("label", "").strip().lower()
            val = f.get("value", "").strip()
            if label == "honeypot" and val:
                logger.warning("Honeypot triggered => potential spam.")
                return JSONResponse({"error": "Spam detected."}, status_code=400)

        # Rate limiting
        now = time.time()
        while RECENT_REQUESTS and (now - RECENT_REQUESTS[0] > SPAM_WINDOW_SECONDS):
            RECENT_REQUESTS.popleft()
        if len(RECENT_REQUESTS) >= MAX_REQUESTS_PER_WINDOW:
            delay = random.uniform(5, 10)
            logger.warning(f"Rate-limit triggered. Will sleep {delay:.1f}s to slow down spam.")
            await asyncio.sleep(delay)
        RECENT_REQUESTS.append(now)

        # Extract Matrix ID from form fields
        matrix_id = None
        for f in fields:
            if f.get("label", "").strip().lower() != "honeypot":
                possible_id = f.get("value", "").strip()
                if possible_id:
                    matrix_id = possible_id
                    break
        if not matrix_id:
            logger.warning("No Matrix ID provided in form fields.")
            return JSONResponse({"error": "No Matrix ID found"}, status_code=400)

        # Fix common Matrix ID format mistakes
        matrix_id = fix_common_mxid_mistakes(matrix_id)

        # Check if user is blocked
        if await is_user_blocked(matrix_id):
            reason = await get_block_reason_if_blocked(matrix_id)
            logger.info(f"{matrix_id} is blocked. Reason: {reason}")
            return JSONResponse({"error": f"User blocked. Reason: {reason}"}, status_code=403)

        # Validate Matrix ID format
        pattern = re.compile(r"^@[a-z0-9._=-]+:[a-z0-9.\-]+\.[a-z]{2,}$")
        if not pattern.match(matrix_id):
            logger.warning(f"Invalid MXID format: {matrix_id}")
            return JSONResponse({"error": "Invalid Matrix ID format"}, status_code=400)

        client: httpx.AsyncClient = request.app.state.httpx_client
        await ensure_matrix_token_valid(client)

        # Check if user exists on the Matrix server
        if not await user_exists(client, MATRIX_ACCESS_TOKEN, matrix_id):
            logger.warning(f"Provided user does not exist: {matrix_id}")
            return JSONResponse({"error": "User not found on this Matrix server"}, status_code=404)

        # Check if user is already in the room
        is_in_room = False
        try:
            is_in_room = await check_user_in_room(client, matrix_id, MATRIX_ACCESS_TOKEN)
        except Exception as e:
            logger.warning(f"membership check failed: {e}")

        if is_in_room:
            logger.info(f"{matrix_id} is already in the room.")
            return JSONResponse({"status": "Already in the room"})

        # Send invite
        ok = await invite_user(client, matrix_id, MATRIX_ACCESS_TOKEN)
        if ok:
            async with PENDING_INVITES_LOCK:
                PENDING_INVITES[matrix_id] = {
                    "invite_time": time.time(),
                    "last_checked": time.time()
                }
                save_pending_invites_to_file()
            return JSONResponse({"status": "Invite sent. Check your messages!"})
        else:
            return JSONResponse({"error": "Invite failed."}, status_code=500)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JSONResponse({"error": "Processing error"}, status_code=500)

@app.post("/block_user")
async def block_user(payload: dict, request: Request, _: bool = Depends(verify_api_key)):
    logger.info("Received request to block user.")
    user_id = payload.get("user_id", "").strip()
    reason = payload.get("reason", "").strip()
    if not user_id:
        logger.warning("user_id not provided in payload.")
        return JSONResponse({"error": "Must provide user_id"}, status_code=400)

    try:
        async with BLOCKLIST_LOCK:
            load_blocklist_from_file()
        await add_user_to_blocklist(user_id, reason)

        # Remove from pending invites
        async with PENDING_INVITES_LOCK:
            if user_id in PENDING_INVITES:
                PENDING_INVITES.pop(user_id, None)
                save_pending_invites_to_file()

        # Kick user if they're in the room
        client: httpx.AsyncClient = request.app.state.httpx_client
        await ensure_matrix_token_valid(client)
        try:
            if await check_user_in_room(client, user_id, MATRIX_ACCESS_TOKEN):
                await kick_user(client, user_id, MATRIX_ACCESS_TOKEN, reason or "User blocked.")
        except Exception as e:
            logger.warning(f"Kick check error: {e}")

        return JSONResponse({"status": f"Blocked {user_id}."})
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JSONResponse({"error": "Error blocking user"}, status_code=500)

@app.post("/unblock_user")
async def unblock_user(payload: dict, _: bool = Depends(verify_api_key)):
    logger.info("Received request to unblock user.")
    user_id = payload.get("user_id", "").strip()
    if not user_id:
        logger.warning("user_id not provided.")
        return JSONResponse({"error": "Must provide user_id"}, status_code=400)
    try:
        await remove_user_from_blocklist(user_id)
        return JSONResponse({"status": f"Unblocked {user_id}."})
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JSONResponse({"error": "Error unblocking"}, status_code=500)

@app.get("/blocklist")
async def list_blocked_users(_: bool = Depends(verify_api_key)):
    logger.info("Returning blocklist to client.")
    async with BLOCKLIST_LOCK:
        load_blocklist_from_file()
        items = [{"user_id": uid, "reason": r} for uid, r in sorted(BLOCKLIST.items())]
    return JSONResponse({"blocked_users": items})

@app.post("/rescind_invite")
async def rescind_invite(payload: dict, request: Request, _: bool = Depends(verify_api_key)):
    logger.info("Received request to rescind invite.")
    user_id = payload.get("user_id", "").strip()
    if not user_id:
        logger.warning("user_id not provided.")
        return JSONResponse({"error": "Must provide user_id"}, status_code=400)
    try:
        client: httpx.AsyncClient = request.app.state.httpx_client
        await ensure_matrix_token_valid(client)

        # Remove from pending invites
        async with PENDING_INVITES_LOCK:
            if user_id in PENDING_INVITES:
                PENDING_INVITES.pop(user_id, None)
                save_pending_invites_to_file()

        # Remove user from room
        try:
            await kick_user(client, user_id, MATRIX_ACCESS_TOKEN, "Invite rescinded.")
        except Exception as e:
            logger.warning(f"Kick error: {e}")

        return JSONResponse({"status": f"Rescinded invite for {user_id}."})
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JSONResponse({"error": "Error rescinding invite"}, status_code=500)

@app.get("/room_members")
async def room_members(request: Request, _: bool = Depends(verify_api_key)):
    """Return the list of all joined members in the configured room."""
    logger.info("Fetching joined room members for debugging.")
    client: httpx.AsyncClient = request.app.state.httpx_client
    await ensure_matrix_token_valid(client)
    data = await with_rate_limit(
        client.get,
        f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/joined_members",
        headers={"Authorization": f"Bearer {MATRIX_ACCESS_TOKEN}"}
    )
    try:
        data.raise_for_status()
        joined = data.json().get("joined", {})
        return JSONResponse({"joined_members": list(joined.keys()), "count": len(joined)})
    except Exception as e:
        logger.error(f"Error reading joined_members: {e}", exc_info=True)
        return JSONResponse({"error": "Error fetching members"}, status_code=500)

@app.get("/pending_invites")
async def get_pending_invites(_: bool = Depends(verify_api_key)):
    """Debug endpoint that shows the current PENDING_INVITES in memory."""
    logger.info("Returning all pending invites.")
    async with PENDING_INVITES_LOCK:
        load_pending_invites_from_file()
        invites_list = []
        for k, v in PENDING_INVITES.items():
            invites_list.append({
                "user_id": k,
                "invite_time": v.get("invite_time"),
                "last_checked": v.get("last_checked"),
                "age_seconds": time.time() - v.get("invite_time", 0)
            })
    return JSONResponse({"pending_invites": invites_list, "count": len(invites_list)})

@app.get("/room_state")
async def get_room_state(request: Request, _: bool = Depends(verify_api_key)):
    """Return the full state of the room for debugging purposes."""
    logger.info("Fetching full room state for debug.")
    client: httpx.AsyncClient = request.app.state.httpx_client
    await ensure_matrix_token_valid(client)
    try:
        state_info = await check_room_state(client, MATRIX_ACCESS_TOKEN)
        return JSONResponse(state_info)
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return JSONResponse({"error": "Error fetching room state"}, status_code=500)

# Background task: Check pending invites periodically
async def check_pending_invites(client: httpx.AsyncClient):
    logger.info("Checking all pending invites for acceptance or expiration.")
    async with PENDING_INVITES_LOCK:
        if not PENDING_INVITES:
            logger.info("No pending invites to check.")
            return
        load_pending_invites_from_file()

    async with BLOCKLIST_LOCK:
        load_blocklist_from_file()

    now = time.time()
    users_to_remove = []
    snapshot = []
    async with PENDING_INVITES_LOCK:
        snapshot = list(PENDING_INVITES.items())

    for user_id, data in snapshot:
        logger.debug(f"Checking user_id={user_id} in snapshot.")
        # Check if user is now blocked
        if await is_user_blocked(user_id):
            reason = await get_block_reason_if_blocked(user_id)
            logger.info(f"{user_id} is blocked => removing from pending & kicking.")
            users_to_remove.append(user_id)
            try:
                if await check_user_in_room(client, user_id, MATRIX_ACCESS_TOKEN):
                    await kick_user(client, user_id, MATRIX_ACCESS_TOKEN, f"Blocked: {reason}")
            except Exception as e:
                logger.warning(f"Kick error for {user_id}: {e}")
            continue

        # Only check membership if enough time has passed since last check
        if now - data["last_checked"] < 100:
            logger.debug(f"{user_id} last checked too recently, skipping.")
            continue

        # Update last checked timestamp
        data["last_checked"] = now
        try:
            is_in_room = await check_user_in_room(client, user_id, MATRIX_ACCESS_TOKEN)
            if is_in_room:
                logger.info(f"{user_id} joined => sending welcome and removing from pending.")
                await send_welcome_message(client, user_id, MATRIX_ACCESS_TOKEN)
                users_to_remove.append(user_id)
            else:
                invite_age = now - data["invite_time"]
                if invite_age > 604800:  # 7 days
                    logger.info(f"{user_id} never joined, invite is older than 7 days => removing.")
                    users_to_remove.append(user_id)
                else:
                    hrs = invite_age / 3600
                    logger.info(f"{user_id} still pending after ~{hrs:.1f} hours.")
        except Exception as e:
            logger.error(f"Error checking membership for {user_id}: {e}", exc_info=True)

    async with PENDING_INVITES_LOCK:
        for user_id in users_to_remove:
            if user_id in PENDING_INVITES:
                PENDING_INVITES.pop(user_id, None)
        save_pending_invites_to_file()

    logger.info(f"Completed. {len(PENDING_INVITES)} invites remain pending.")

async def periodic_invite_checker(app: FastAPI):
    """Periodic task that checks pending invites every 5 minutes."""
    logger.debug("Starting background task for checking invites.")
    client = app.state.httpx_client
    while True:
        try:
            logger.debug("Invoking check_pending_invites.")
            await check_pending_invites(client)
            logger.debug("Sleeping 5 minutes.")
            await asyncio.sleep(100)  # 5 minutes
        except asyncio.CancelledError:
            logger.info("Task cancelled, shutting down.")
            break
        except Exception as e:
            logger.error(f"Error in loop: {e}", exc_info=True)
            await asyncio.sleep(60)

# Background task: Scan room members for blocklist violations
async def scan_room_members_for_blocklist(client: httpx.AsyncClient):
    """List all joined members in the room and kick them if they're on the blocklist."""
    logger.info("Scanning all joined members to enforce blocklist.")
    url = f"{MATRIX_BASE_URL}/_matrix/client/v3/rooms/{NEW_ROOM_ID}/joined_members"
    headers = {"Authorization": f"Bearer {MATRIX_ACCESS_TOKEN}"}

    async def make_request():
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()

    try:
        data = await with_rate_limit(make_request)
        joined = data.get("joined", {})
        logger.info(f"Found {len(joined)} joined members in the room.")
        async with BLOCKLIST_LOCK:
            load_blocklist_from_file()

        for member_id in joined.keys():
            if await is_user_blocked(member_id):
                reason = await get_block_reason_if_blocked(member_id)
                logger.info(f"Kicking blocked user {member_id} (Reason: {reason}).")
                await kick_user(client, member_id, MATRIX_ACCESS_TOKEN, reason or "User blocked.")
    except Exception as e:
        logger.error(f"Error scanning membership: {e}", exc_info=True)

async def periodic_member_blocklist_checker(app: FastAPI):
    """Background task that runs every 10 minutes to check membership against blocklist."""
    logger.debug("Starting background task to enforce blocklist membership checks.")
    client = app.state.httpx_client
    while True:
        try:
            logger.debug("Running scan_room_members_for_blocklist.")
            await scan_room_members_for_blocklist(client)
            logger.debug("Sleeping 10 minutes.")
            await asyncio.sleep(600)  # 10 minutes
        except asyncio.CancelledError:
            logger.info("Task cancelled, shutting down.")
            break
        except Exception as e:
            logger.error(f"Error: {e}", exc_info=True)
            await asyncio.sleep(60)

# CLI and server startup
if __name__ == "__main__":
    # Normal server startup
    uvicorn.run("mknock:app", host="0.0.0.0", port=8000, reload=True)
