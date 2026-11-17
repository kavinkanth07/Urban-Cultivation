"""
Urban Cultivation - connecting farmers with unused urban land.

A command-line platform (Python + MySQL) where landowners list unused land
and farmers lease it for cultivation, without a middleman.

Class XII Computer Science project (CBSE, 2023-24), cleaned up for GitHub.

Security notes
  * Users log in with Aadhaar + a password. Passwords are stored only as
    salted PBKDF2-SHA256 hashes, never as plain text.
  * Aadhaar and PAN numbers are never stored. The database keeps only a keyed
    fingerprint (HMAC-SHA256) of each, so duplicates can be detected, plus the
    last 4 Aadhaar digits for display (XXXX XXXX 1234).
  * The HMAC key comes from the APP_SECRET environment variable, or from the
    file .urban_secret next to this script (created on first run). Keep it
    safe and never upload it: if it is lost, nobody can log in again.
  * Every input is checked against its real-world format before it is saved.

Setup: see README.md. Database settings come from environment variables
(DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME); anything not set is asked
for, so no password is ever stored in the code.
"""
import hashlib
import hmac
import os
import re
import secrets
import sys
from decimal import Decimal
from getpass import getpass
from pathlib import Path

import mysql.connector
from mysql.connector import errorcode

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS farmer (
        farmer_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(60) NOT NULL,
        aadhaar_hash CHAR(64) NOT NULL UNIQUE,
        aadhaar_last4 CHAR(4) NOT NULL,
        pan_hash CHAR(64) NOT NULL UNIQUE,
        contact CHAR(10) NOT NULL,
        password_hash VARCHAR(160) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS landowner (
        landowner_id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(60) NOT NULL,
        aadhaar_hash CHAR(64) NOT NULL UNIQUE,
        aadhaar_last4 CHAR(4) NOT NULL,
        pan_hash CHAR(64) NOT NULL UNIQUE,
        contact CHAR(10) NOT NULL,
        password_hash VARCHAR(160) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""",
    """CREATE TABLE IF NOT EXISTS land (
        land_id INT AUTO_INCREMENT PRIMARY KEY,
        landowner_id INT NOT NULL,
        name VARCHAR(60) NOT NULL,
        contact CHAR(10) NOT NULL,
        location VARCHAR(100) NOT NULL,
        size_acres DECIMAL(6, 2) NOT NULL CHECK (size_acres > 0),
        monthly_rent INT UNSIGNED NOT NULL CHECK (monthly_rent > 0),
        is_listed BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (landowner_id) REFERENCES landowner(landowner_id))""",
    """CREATE TABLE IF NOT EXISTS lease (
        lease_id INT AUTO_INCREMENT PRIMARY KEY,
        farmer_id INT NOT NULL,
        land_id INT NOT NULL,
        months TINYINT UNSIGNED NOT NULL CHECK (months BETWEEN 1 AND 120),
        monthly_rent INT UNSIGNED NOT NULL,
        status ENUM('pending', 'approved', 'rejected', 'cancelled', 'ended')
               NOT NULL DEFAULT 'pending',
        requested_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        start_date DATE NULL,
        end_date DATE NULL,
        FOREIGN KEY (farmer_id) REFERENCES farmer(farmer_id),
        FOREIGN KEY (land_id) REFERENCES land(land_id))""",
]

# Table names can't be passed as %s parameters, so the role is only ever
# taken from this fixed dictionary - user input never reaches the SQL text.
ROLES = {"1": "farmer", "2": "landowner"}

MAX_ACRES = Decimal("1000")
MIN_RENT, MAX_RENT = 100, 10_00_000          # rupees per month
MAX_MONTHS = 120                             # 10 years
PBKDF2_ROUNDS = 200_000
SECRET_FILE = Path(__file__).with_name(".urban_secret")
SECRET_KEY = b""                             # loaded in main()


# ---------- security helpers ----------

def load_secret():
    """Key for fingerprinting Aadhaar/PAN: env var, else local file (created once)."""
    env = os.getenv("APP_SECRET")
    if env:
        return env.encode()
    if SECRET_FILE.exists():
        return SECRET_FILE.read_bytes().strip()
    key = secrets.token_hex(32).encode()
    SECRET_FILE.write_bytes(key)
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
    print(f"Created a new secret key in {SECRET_FILE.name}. "
          "Back it up and never upload it - without it nobody can log in.")
    return key


def fingerprint(kind, value):
    """Keyed one-way hash: same input -> same output, but can't be reversed."""
    return hmac.new(SECRET_KEY, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def check_password(password, stored):
    try:
        _, rounds, salt, digest = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                  bytes.fromhex(salt), int(rounds))
    except ValueError:
        return False
    return hmac.compare_digest(new.hex(), digest)


_DUMMY_HASH = None


def dummy_hash():
    """Checked when an account doesn't exist, so a wrong Aadhaar takes as long as a wrong password."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_hex(8))
    return _DUMMY_HASH


# ---------- input validation ----------
# Each check function takes the raw text the user typed and either returns the
# cleaned value or raises ValueError with a message saying what format is expected.

class Cancelled(Exception):
    """Raised when the user types 'cancel' to go back to the menu."""


def clean_spaces(text):
    return " ".join(text.split())


def v_person_name(raw):
    name = clean_spaces(raw)
    if not 2 <= len(name) <= 60:
        raise ValueError("Name must be 2-60 characters long.")
    if not re.fullmatch(r"[A-Za-z]+(?:(?:\. ?| |'|-)[A-Za-z]+)*\.?", name):
        raise ValueError("Name can only have letters, spaces, dots, hyphens and "
                         "apostrophes (e.g. S. Kavin Kumar).")
    return name


# Verhoeff checksum tables - the last digit of every Aadhaar is a Verhoeff check digit.
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
      [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
      [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
      [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
      [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
      [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_ok(number):
    check = 0
    for i, digit in enumerate(reversed(number)):
        check = _D[check][_P[i % 8][int(digit)]]
    return check == 0


def v_aadhaar(raw):
    digits = re.sub(r"[\s-]", "", raw)
    if not re.fullmatch(r"\d{12}", digits):
        raise ValueError("Aadhaar must be exactly 12 digits (spaces allowed, e.g. XXXX XXXX XXXX).")
    if digits[0] in "01":
        raise ValueError("A real Aadhaar number never starts with 0 or 1.")
    if not verhoeff_ok(digits):
        raise ValueError("This is not a valid Aadhaar number (its check digit doesn't match). "
                         "Please re-check it.")
    return digits


PAN_HOLDER_TYPES = "ABCFGHJLPT"   # 4th character: P = person, C = company, H = HUF, F = firm ...


def v_pan(raw):
    pan = re.sub(r"\s", "", raw).upper()
    if not re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", pan):
        raise ValueError("PAN must be 10 characters: 5 letters, 4 digits, 1 letter (e.g. ABCPE1234F).")
    if pan[3] not in PAN_HOLDER_TYPES:
        raise ValueError(f"The 4th letter of a PAN shows the holder type "
                         f"({', '.join(PAN_HOLDER_TYPES)}; P for a person). '{pan[3]}' is not valid.")
    if pan[5:9] == "0000":
        raise ValueError("The 4 digits in a PAN can't be 0000.")
    return pan


def v_phone(raw):
    number = re.sub(r"[\s-]", "", raw)
    number = re.sub(r"^(?:\+91|0091|91|0)(?=\d{10}$)", "", number)
    if not re.fullmatch(r"[6-9]\d{9}", number):
        raise ValueError("Enter a 10-digit Indian mobile number starting with 6, 7, 8 or 9 "
                         "(+91 is optional).")
    if len(set(number)) == 1:
        raise ValueError("That doesn't look like a real phone number.")
    return number


def v_new_password(raw):
    if not 8 <= len(raw) <= 64:
        raise ValueError("Password must be 8-64 characters long.")
    if not (re.search(r"[A-Za-z]", raw) and re.search(r"\d", raw)):
        raise ValueError("Password must contain at least one letter and one digit.")
    return raw


def v_nonempty(raw):
    if not raw:
        raise ValueError("This can't be empty.")
    return raw


def v_text(label, low, high):
    """Land names, locations: letters, digits and common address punctuation only."""
    def check(raw):
        text = clean_spaces(raw)
        if not low <= len(text) <= high:
            raise ValueError(f"{label} must be {low}-{high} characters long.")
        if not re.fullmatch(r"[A-Za-z0-9 .,'&()/#-]+", text):
            raise ValueError(f"{label} can only have letters, numbers, spaces and . , ' & ( ) / # -")
        if not re.search(r"[A-Za-z]", text):
            raise ValueError(f"{label} must contain at least one letter.")
        return text
    return check


v_land_name = v_text("Land name", 3, 60)
v_location = v_text("Location", 3, 100)


def v_acres(raw):
    if not re.fullmatch(r"\d{1,4}(?:\.\d{1,2})?", raw):
        raise ValueError("Enter the size in acres as a number with up to 2 decimals (e.g. 2 or 0.75).")
    size = Decimal(raw)
    if not Decimal("0.01") <= size <= MAX_ACRES:
        raise ValueError(f"Size must be between 0.01 and {MAX_ACRES} acres.")
    return size


def v_rent(raw):
    text = re.sub(r"^(?:rs\.?|inr|₹)\s*", "", raw, flags=re.IGNORECASE).replace(",", "")
    if not re.fullmatch(r"\d{1,7}", text):
        raise ValueError("Enter the rent in whole rupees, e.g. 5000 or 5,000.")
    rent = int(text)
    if not MIN_RENT <= rent <= MAX_RENT:
        raise ValueError(f"Monthly rent must be between Rs. {MIN_RENT:,} and Rs. {MAX_RENT:,}.")
    return rent


def v_months(raw):
    if not re.fullmatch(r"\d{1,3}", raw) or not 1 <= int(raw) <= MAX_MONTHS:
        raise ValueError(f"Enter the number of months, from 1 to {MAX_MONTHS}.")
    return int(raw)


def v_id(raw):
    if not re.fullmatch(r"[1-9]\d{0,8}", raw):
        raise ValueError("Enter the ID number shown in the list.")
    return int(raw)


def v_yes_no(raw):
    answer = raw.lower()
    if answer in ("y", "yes"):
        return True
    if answer in ("n", "no"):
        return False
    raise ValueError("Please type yes or no.")


def v_choice(count):
    def check(raw):
        if not (raw.isdigit() and 1 <= int(raw) <= count):
            raise ValueError(f"Please enter a number from 1 to {count}.")
        return int(raw)
    return check


def ask(prompt, check, secret=False, default=None):
    """Ask until check() accepts the answer. 'cancel' goes back; Enter keeps the default."""
    while True:
        raw = (getpass if secret else input)(prompt).strip()
        if raw.lower() == "cancel":
            raise Cancelled
        if raw == "" and default is not None:
            return default
        try:
            return check(raw)
        except ValueError as err:
            print(f"  ! {err}")


def ask_role():
    print("1 = Farmer, 2 = Landowner")
    return ROLES[str(ask("Enter your role (1/2): ", v_choice(2)))]


def ask_new_password():
    print("Password: 8-64 characters, with at least one letter and one digit "
          "(it won't show on screen as you type).")
    while True:
        password = ask("Choose a password: ", v_new_password, secret=True)
        if ask("Type it again: ", v_nonempty, secret=True) == password:
            return password
        print("  ! The two passwords don't match. Try again.")


# ---------- display helpers ----------

def cut(value, width):
    text = str(value)
    return text if len(text) <= width else text[:width - 1] + "~"


def rupees(amount):
    return f"Rs. {amount:,}"


def mask_aadhaar(last4):
    return f"XXXX XXXX {last4}"


# ---------- database ----------

def connect():
    """Connect to the app's MySQL database and create the tables if needed."""
    name = os.getenv("DB_NAME", "urban_cultivation")
    user = os.getenv("DB_USER") or input("MySQL user name [urban_app]: ").strip() or "urban_app"
    password = os.getenv("DB_PASSWORD")
    if password is None:
        password = getpass(f"MySQL password for {user}: ")
    try:
        port = int(os.getenv("DB_PORT", "3306"))
    except ValueError:
        sys.exit("DB_PORT must be a number, e.g. 3306.")
    try:
        db = mysql.connector.connect(host=os.getenv("DB_HOST", "localhost"), port=port,
                                     user=user, password=password, database=name,
                                     autocommit=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            sys.exit("Could not connect: wrong MySQL user name or password.")
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            sys.exit(f"Database '{name}' does not exist. Run schema.sql first (see README.md).")
        if err.errno == errorcode.ER_DBACCESS_DENIED_ERROR:
            sys.exit(f"User '{user}' has no access to '{name}'. Run schema.sql (see README.md).")
        sys.exit(f"Could not connect to MySQL: {err}")
    cur = db.cursor()
    for statement in SCHEMA:
        cur.execute(statement)
    # Tables from the old version have no password column and can't be reused.
    cur.execute("""SELECT COUNT(*) FROM information_schema.columns
                   WHERE table_schema = DATABASE() AND table_name = 'farmer'
                     AND column_name = 'password_hash'""")
    if cur.fetchone()[0] == 0:
        db.close()
        sys.exit("Found tables from the old version of this program. Delete them first:\n"
                 "  DROP TABLE lease, land, farmer, landowner;")
    return db


def expire_leases(db):
    """Approved leases whose end date has passed become 'ended'."""
    db.cursor().execute("""UPDATE lease SET status = 'ended'
                           WHERE status = 'approved' AND end_date < CURDATE()""")


def account_exists(db, role, column, value):
    assert column in ("aadhaar_hash", "pan_hash")
    cur = db.cursor()
    cur.execute(f"SELECT 1 FROM {role} WHERE {column} = %s", (value,))
    return cur.fetchone() is not None


# ---------- accounts ----------

def register_user(db):
    print("\n=== Register ===  (type 'cancel' at any prompt to go back)")
    role = ask_role()
    name = ask("Full name: ", v_person_name)
    aadhaar = ask("Aadhaar number (12 digits): ", v_aadhaar)
    aadhaar_hash = fingerprint("aadhaar", aadhaar)
    if account_exists(db, role, "aadhaar_hash", aadhaar_hash):
        print(f"A {role} account with this Aadhaar already exists. Please log in.")
        return None, None
    pan = ask("PAN (e.g. ABCPE1234F): ", v_pan)
    pan_hash = fingerprint("pan", pan)
    if account_exists(db, role, "pan_hash", pan_hash):
        print(f"A {role} account with this PAN already exists. Please log in.")
        return None, None
    contact = ask("Mobile number: ", v_phone)
    password = ask_new_password()
    cur = db.cursor()
    try:
        cur.execute(f"""INSERT INTO {role}
                        (name, aadhaar_hash, aadhaar_last4, pan_hash, contact, password_hash)
                        VALUES (%s, %s, %s, %s, %s, %s)""",
                    (name, aadhaar_hash, aadhaar[-4:], pan_hash, contact, hash_password(password)))
    except mysql.connector.IntegrityError:
        print("An account with this Aadhaar or PAN already exists. Please log in.")
        return None, None
    print(f"Registered as a {role}, {name} (Aadhaar {mask_aadhaar(aadhaar[-4:])}). "
          "You are now logged in.")
    return cur.lastrowid, role


def login_user(db):
    print("\n=== Login ===  (type 'cancel' at any prompt to go back)")
    role = ask_role()
    aadhaar = ask("Aadhaar number: ", v_aadhaar)
    cur = db.cursor(dictionary=True)
    cur.execute(f"SELECT {role}_id AS id, name, password_hash FROM {role} WHERE aadhaar_hash = %s",
                (fingerprint("aadhaar", aadhaar),))
    user = cur.fetchone()
    for attempts_left in (2, 1, 0):
        password = ask("Password: ", v_nonempty, secret=True)
        stored = user["password_hash"] if user else dummy_hash()
        if check_password(password, stored) and user:
            print(f"Login successful! Welcome, {user['name']}.")
            return user["id"], role
        print("  ! Wrong Aadhaar number or password."
              + (f" {attempts_left} attempt(s) left." if attempts_left else ""))
    print("Too many wrong attempts. Back to the main menu.")
    return None, None


# ---------- landowner features ----------

def fetch_my_lands(db, landowner_id):
    cur = db.cursor(dictionary=True)
    cur.execute("""SELECT l.land_id, l.name, l.location, l.size_acres, l.monthly_rent,
                          l.contact, l.is_listed, a.farmer_name, a.end_date,
                          (SELECT COUNT(*) FROM lease p
                           WHERE p.land_id = l.land_id AND p.status = 'pending') AS pending
                   FROM land l
                   LEFT JOIN (SELECT ls.land_id, f.name AS farmer_name, ls.end_date
                              FROM lease ls JOIN farmer f ON f.farmer_id = ls.farmer_id
                              WHERE ls.status = 'approved') a ON a.land_id = l.land_id
                   WHERE l.landowner_id = %s
                   ORDER BY l.is_listed DESC, l.land_id""", (landowner_id,))
    return cur.fetchall()


def show_my_lands(lands):
    print(f"{'ID':>4}  {'Name':<18} {'Location':<18} {'Acres':>7} {'Rent/month':>12}  Status")
    for land in lands:
        if not land["is_listed"]:
            status = "Removed"
        elif land["farmer_name"]:
            status = f"Leased to {cut(land['farmer_name'], 16)} till {land['end_date']:%d-%m-%Y}"
        else:
            status = "Available"
            if land["pending"]:
                status += f" ({land['pending']} request(s) waiting)"
        print(f"{land['land_id']:>4}  {cut(land['name'], 18):<18} {cut(land['location'], 18):<18} "
              f"{land['size_acres']:>7} {rupees(land['monthly_rent']):>12}  {status}")


def display_my_lands(db, landowner_id):
    print("\n=== My Lands ===")
    lands = fetch_my_lands(db, landowner_id)
    if lands:
        show_my_lands(lands)
    else:
        print("You have not listed any land yet.")


def pick_my_land(db, landowner_id, action):
    """Show the owner's listed lands and return the one they choose (or None)."""
    lands = [land for land in fetch_my_lands(db, landowner_id) if land["is_listed"]]
    if not lands:
        print("You have no listed land.")
        return None
    show_my_lands(lands)
    land_id = ask(f"Enter the Land ID to {action}: ", v_id)
    land = next((land for land in lands if land["land_id"] == land_id), None)
    if land is None:
        print("That ID is not one of your listed lands.")
    return land


def owner_contact(db, landowner_id):
    cur = db.cursor()
    cur.execute("SELECT contact FROM landowner WHERE landowner_id = %s", (landowner_id,))
    return cur.fetchone()[0]


def add_land(db, landowner_id):
    print("\n=== Add Land ===  (type 'cancel' at any prompt to go back)")
    name = ask("Name of the land (e.g. Plot 4, Green Acres): ", v_land_name)
    location = ask("Location (area, city): ", v_location)
    size = ask("Size (acres): ", v_acres)
    rent = ask("Monthly rent (Rs.): ", v_rent)
    my_number = owner_contact(db, landowner_id)
    contact = ask(f"Contact number for this land [Enter = {my_number}]: ", v_phone,
                  default=my_number)
    print(f"\n{name}, {location} - {size} acres at {rupees(rent)}/month, contact {contact}")
    if not ask("Add this land? (yes/no): ", v_yes_no):
        print("Not added.")
        return
    db.cursor().execute("""INSERT INTO land
                           (landowner_id, name, contact, location, size_acres, monthly_rent)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (landowner_id, name, contact, location, size, rent))
    print("Land added successfully!")


def edit_land(db, landowner_id):
    print("\n=== Edit Land ===  (press Enter to keep the current value)")
    land = pick_my_land(db, landowner_id, "edit")
    if land is None:
        return
    name = ask(f"Name [{land['name']}]: ", v_land_name, default=land["name"])
    location = ask(f"Location [{land['location']}]: ", v_location, default=land["location"])
    size = ask(f"Size in acres [{land['size_acres']}]: ", v_acres, default=land["size_acres"])
    rent = ask(f"Monthly rent [{land['monthly_rent']}]: ", v_rent, default=land["monthly_rent"])
    contact = ask(f"Contact [{land['contact']}]: ", v_phone, default=land["contact"])
    db.cursor().execute("""UPDATE land SET name = %s, location = %s, size_acres = %s,
                                           monthly_rent = %s, contact = %s
                           WHERE land_id = %s AND landowner_id = %s""",
                        (name, location, size, rent, contact, land["land_id"], landowner_id))
    print("Land updated. (A rent change applies to new requests, not existing leases.)")


def remove_land(db, landowner_id):
    print("\n=== Remove Land ===")
    land = pick_my_land(db, landowner_id, "remove")
    if land is None:
        return
    if land["farmer_name"]:
        print(f"This land is leased to {land['farmer_name']} until "
              f"{land['end_date']:%d-%m-%Y}. It can be removed after the lease ends.")
        return
    if not ask(f"Remove '{land['name']}' from the listings? Waiting requests will be "
               "rejected. (yes/no): ", v_yes_no):
        print("Not removed.")
        return
    db.start_transaction()
    try:
        cur = db.cursor()
        cur.execute("UPDATE land SET is_listed = FALSE WHERE land_id = %s AND landowner_id = %s",
                    (land["land_id"], landowner_id))
        cur.execute("UPDATE lease SET status = 'rejected' WHERE land_id = %s AND status = 'pending'",
                    (land["land_id"],))
        db.commit()
    except mysql.connector.Error:
        db.rollback()
        raise
    print("Land removed from the listings.")


def review_requests(db, landowner_id):
    print("\n=== Lease Requests ===")
    cur = db.cursor(dictionary=True)
    cur.execute("""SELECT ls.lease_id, l.name AS land, f.name AS farmer, f.contact,
                          ls.months, ls.monthly_rent
                   FROM lease ls
                   JOIN land l ON l.land_id = ls.land_id
                   JOIN farmer f ON f.farmer_id = ls.farmer_id
                   WHERE l.landowner_id = %s AND ls.status = 'pending'
                   ORDER BY ls.requested_on""", (landowner_id,))
    requests = cur.fetchall()
    if not requests:
        print("No requests are waiting.")
        return
    print(f"{'Req':>4}  {'Land':<18} {'Farmer':<18} {'Contact':<11} {'Months':>6} {'Rent/month':>12}")
    for r in requests:
        print(f"{r['lease_id']:>4}  {cut(r['land'], 18):<18} {cut(r['farmer'], 18):<18} "
              f"{r['contact']:<11} {r['months']:>6} {rupees(r['monthly_rent']):>12}")
    lease_id = ask("Enter the Request number to answer: ", v_id)
    request = next((r for r in requests if r["lease_id"] == lease_id), None)
    if request is None:
        print("That is not one of the waiting requests.")
        return
    print("1 = Approve, 2 = Reject")
    if ask("Your decision (1/2): ", v_choice(2)) == 2:
        db.cursor().execute("UPDATE lease SET status = 'rejected' "
                            "WHERE lease_id = %s AND status = 'pending'", (lease_id,))
        print("Request rejected.")
        return
    # Approve inside a transaction, locking the land row, so two approvals
    # can never both succeed for the same land.
    db.start_transaction()
    try:
        cur = db.cursor()
        cur.execute("""SELECT l.land_id FROM land l JOIN lease ls ON ls.land_id = l.land_id
                       WHERE ls.lease_id = %s AND l.is_listed FOR UPDATE""", (lease_id,))
        row = cur.fetchone()
        if row is None:
            db.rollback()
            print("This land is no longer listed.")
            return
        land_id = row[0]
        cur.execute("SELECT COUNT(*) FROM lease WHERE land_id = %s AND status = 'approved'",
                    (land_id,))
        if cur.fetchone()[0]:
            db.rollback()
            print("This land is already leased to someone else.")
            return
        cur.execute("""UPDATE lease SET status = 'approved', start_date = CURDATE(),
                              end_date = DATE_SUB(DATE_ADD(CURDATE(), INTERVAL months MONTH),
                                                  INTERVAL 1 DAY)
                       WHERE lease_id = %s AND status = 'pending'""", (lease_id,))
        if cur.rowcount != 1:
            db.rollback()
            print("The farmer has cancelled this request.")
            return
        cur.execute("""UPDATE lease SET status = 'rejected'
                       WHERE land_id = %s AND status = 'pending'""", (land_id,))
        db.commit()
    except mysql.connector.Error:
        db.rollback()
        raise
    print(f"Approved! '{request['land']}' is leased to {request['farmer']} for "
          f"{request['months']} month(s). Other requests for this land were rejected.")


# ---------- farmer features ----------

def available_lands(db):
    cur = db.cursor(dictionary=True)
    cur.execute("""SELECT l.land_id, l.name, l.location, l.size_acres, l.monthly_rent
                   FROM land l
                   WHERE l.is_listed AND NOT EXISTS (
                       SELECT 1 FROM lease ls WHERE ls.land_id = l.land_id
                                                AND ls.status = 'approved')
                   ORDER BY l.land_id""")
    return cur.fetchall()


def display_available_lands(db, _farmer_id=None):
    print("\n=== Available Lands ===")
    lands = available_lands(db)
    if not lands:
        print("No lands are available right now.")
        return lands
    print(f"{'ID':>4}  {'Name':<20} {'Location':<22} {'Acres':>7} {'Rent/month':>12}")
    for land in lands:
        print(f"{land['land_id']:>4}  {cut(land['name'], 20):<20} {cut(land['location'], 22):<22} "
              f"{land['size_acres']:>7} {rupees(land['monthly_rent']):>12}")
    return lands


def request_lease(db, farmer_id):
    lands = display_available_lands(db)
    if not lands:
        return
    land_id = ask("Enter the Land ID you want to lease: ", v_id)
    land = next((land for land in lands if land["land_id"] == land_id), None)
    if land is None:
        print("That land is not in the available list.")
        return
    cur = db.cursor()
    cur.execute("SELECT 1 FROM lease WHERE farmer_id = %s AND land_id = %s AND status = 'pending'",
                (farmer_id, land_id))
    if cur.fetchone():
        print("You have already requested this land. Wait for the landowner's answer.")
        return
    months = ask(f"For how many months? (1-{MAX_MONTHS}): ", v_months)
    total = land["monthly_rent"] * months
    print(f"\n'{land['name']}' in {land['location']} ({land['size_acres']} acres)")
    print(f"{rupees(land['monthly_rent'])}/month x {months} month(s) = {rupees(total)} in total")
    if not ask("Send the lease request? (yes/no): ", v_yes_no):
        print("Request not sent.")
        return
    cur.execute("INSERT INTO lease (farmer_id, land_id, months, monthly_rent) VALUES (%s, %s, %s, %s)",
                (farmer_id, land_id, months, land["monthly_rent"]))
    print("Request sent! The landowner will approve or reject it - check 'My leases'.")


def fetch_my_leases(db, farmer_id):
    cur = db.cursor(dictionary=True)
    cur.execute("""SELECT ls.lease_id, ls.status, ls.months, ls.monthly_rent,
                          ls.start_date, ls.end_date, l.name, l.location, l.contact
                   FROM lease ls JOIN land l ON l.land_id = ls.land_id
                   WHERE ls.farmer_id = %s
                   ORDER BY FIELD(ls.status, 'approved', 'pending', 'ended',
                                  'rejected', 'cancelled'), ls.requested_on DESC""",
                (farmer_id,))
    return cur.fetchall()


def show_my_leases(leases):
    print(f"{'Req':>4}  {'Land':<18} {'Location':<18} {'Months':>6} {'Rent/month':>12}  Status")
    for ls in leases:
        if ls["status"] == "approved":
            status = (f"Active {ls['start_date']:%d-%m-%Y} to {ls['end_date']:%d-%m-%Y}, "
                      f"owner's contact {ls['contact']}")
        elif ls["status"] == "pending":
            status = "Waiting for landowner"
        else:
            status = ls["status"].title()
        print(f"{ls['lease_id']:>4}  {cut(ls['name'], 18):<18} {cut(ls['location'], 18):<18} "
              f"{ls['months']:>6} {rupees(ls['monthly_rent']):>12}  {status}")


def display_my_leases(db, farmer_id):
    print("\n=== My Leases and Requests ===")
    leases = fetch_my_leases(db, farmer_id)
    if leases:
        show_my_leases(leases)
    else:
        print("You have not requested any land yet.")


def cancel_or_end_lease(db, farmer_id):
    print("\n=== Cancel a Request / End a Lease ===")
    leases = [ls for ls in fetch_my_leases(db, farmer_id)
              if ls["status"] in ("pending", "approved")]
    if not leases:
        print("You have no waiting requests or active leases.")
        return
    show_my_leases(leases)
    lease_id = ask("Enter the Request number: ", v_id)
    lease = next((ls for ls in leases if ls["lease_id"] == lease_id), None)
    if lease is None:
        print("That number is not in the list.")
        return
    if lease["status"] == "pending":
        if ask("Cancel this request? (yes/no): ", v_yes_no):
            db.cursor().execute("UPDATE lease SET status = 'cancelled' "
                                "WHERE lease_id = %s AND farmer_id = %s AND status = 'pending'",
                                (lease_id, farmer_id))
            print("Request cancelled.")
    elif ask(f"End your lease of '{lease['name']}' early, today? (yes/no): ", v_yes_no):
        db.cursor().execute("UPDATE lease SET status = 'ended', end_date = CURDATE() "
                            "WHERE lease_id = %s AND farmer_id = %s AND status = 'approved'",
                            (lease_id, farmer_id))
        print("Lease ended. The land is available to others again.")


# ---------- menus ----------

MENUS = {
    "landowner": [("Display my lands", display_my_lands),
                  ("Add new land", add_land),
                  ("Edit a land", edit_land),
                  ("Remove a land", remove_land),
                  ("Lease requests (approve / reject)", review_requests)],
    "farmer": [("Display available lands", display_available_lands),
               ("Request to lease a land", request_lease),
               ("My leases and requests", display_my_leases),
               ("Cancel a request / end a lease", cancel_or_end_lease)],
}


def run_safely(func, *args, fallback=None):
    """Run a feature; 'cancel' or a database error returns to the menu instead of crashing."""
    try:
        return func(*args)
    except Cancelled:
        print("Cancelled - back to the menu.")
    except mysql.connector.Error as err:
        try:
            db = args[0]
            if db.in_transaction:
                db.rollback()
        except mysql.connector.Error:
            pass
        print(f"Database problem: {err.msg}. Please try again.")
    return fallback


def user_menu(db, user_id, role):
    options = MENUS[role]
    count = len(options) + 1
    while True:
        run_safely(expire_leases, db)
        print(f"\n=== {role.title()} Menu ===")
        for i, (label, _) in enumerate(options, 1):
            print(f"{i}. {label}")
        print(f"{count}. Logout")
        try:
            choice = ask(f"Enter your choice (1-{count}): ", v_choice(count))
        except Cancelled:
            continue
        if choice == count:
            print("Logged out.")
            return
        run_safely(options[choice - 1][1], db, user_id)


def main():
    global SECRET_KEY
    SECRET_KEY = load_secret()
    db = connect()
    print("\n******  URBAN CULTIVATION  ******")
    print("Connecting farmers with unused land")
    try:
        while True:
            print("\n=== Main Menu ===\n1. Register\n2. Login\n3. Exit")
            try:
                choice = ask("Enter your choice (1/2/3): ", v_choice(3))
            except Cancelled:
                continue
            if choice == 3:
                break
            action = register_user if choice == 1 else login_user
            user_id, role = run_safely(action, db, fallback=(None, None))
            if user_id:
                user_menu(db, user_id, role)
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        db.close()
        print("Thank you for your time. Exiting program.")


if __name__ == "__main__":
    main()
