import os
import sys
import json
import base64
import hashlib
import secrets
import string
import time
import threading
import datetime
import getpass
import re
import pyperclip
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import zlib

# Encryption libraries
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import pyperclip

    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext, filedialog

    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

try:
    import qrcode

    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

class SecurityLevel(Enum):
    """Security levels for password generation"""
    WEAK = "weak"
    MEDIUM = "medium"
    STRONG = "strong"
    MILITARY = "military"


class Config:
    """Configuration settings for Password Manager"""

    # Security settings
    SALT_SIZE = 32  # bytes
    KEY_SIZE = 32  # bytes (256-bit)
    IV_SIZE = 16  # bytes (128-bit)
    ITERATIONS = 100000  # PBKDF2 iterations
    HASH_ALGORITHM = hashes.SHA256()

    # Password settings
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    DEFAULT_PASSWORD_LENGTH = 16

    # Auto-lock settings
    AUTO_LOCK_TIMEOUT = 300  # seconds (5 minutes)
    CLIPBOARD_CLEAR_TIMEOUT = 30  # seconds

    # Database settings
    DB_FILE = "data/password_manager.db"
    BACKUP_FILE = "data/password_manager_backup.db"
    EXPORT_FILE = "data/password_manager_export.json"

    # Security questions for recovery
    SECURITY_QUESTIONS = [
        "What is your mother's maiden name?",
        "What was your first pet's name?",
        "What city were you born in?",
        "What is your favorite book?",
        "What was your first school?",
        "What is your favorite color?"
    ]

    # Logging
    LOG_FILE = "logs/password_manager.log"
    LOG_LEVEL = "INFO"

@dataclass
class PasswordEntry:
    """Represents a single password entry"""
    id: str
    title: str
    username: str
    password: str  # Encrypted
    url: str
    notes: str
    category: str
    created_at: str
    updated_at: str
    last_used: str
    strength: str
    favorite: bool

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)

    def get_secure_dict(self) -> Dict:
        """Get dictionary without sensitive data"""
        data = self.to_dict()
        data['password'] = '********'  # Mask password
        return data


@dataclass
class SecurityQuestion:
    """Security question for account recovery"""
    question: str
    answer: str  # Encrypted


@dataclass
class BackupInfo:
    """Information about a backup"""
    timestamp: str
    file_path: str
    entry_count: int
    size: int

class EncryptionEngine:
    """
    Handles all encryption and decryption operations
    Uses AES-256-CBC with PBKDF2 key derivation
    """

    def __init__(self):
        """Initialize encryption engine"""
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography module not installed. Install with: pip install cryptography")

        self.backend = default_backend()
        self.master_key = None
        self.salt = None

    def generate_key(self, master_password: str, salt: bytes = None) -> bytes:
        """
        Generate encryption key from master password using PBKDF2

        Args:
            master_password: Master password
            salt: Salt bytes (generates new if None)

        Returns:
            Derived encryption key
        """
        if salt is None:
            salt = os.urandom(Config.SALT_SIZE)
            self.salt = salt
        else:
            self.salt = salt

        # Create PBKDF2 key derivation function
        kdf = PBKDF2HMAC(
            algorithm=Config.HASH_ALGORITHM,
            length=Config.KEY_SIZE,
            salt=salt,
            iterations=Config.ITERATIONS,
            backend=self.backend
        )

        # Derive key
        key = kdf.derive(master_password.encode('utf-8'))
        self.master_key = key
        return key

    def encrypt(self, data: str) -> Dict[str, str]:
        """
        Encrypt data using AES-256-CBC

        Args:
            data: Data to encrypt

        Returns:
            Dictionary with IV and encrypted data
        """
        if not self.master_key:
            raise ValueError("Master key not set. Call generate_key first.")

        # Generate random IV
        iv = os.urandom(Config.IV_SIZE)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()

        # Pad data to block size
        padded_data = self._pad(data.encode('utf-8'))

        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Return IV and encrypted data as base64
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(encrypted_data).decode('utf-8')
        }

    def decrypt(self, encrypted_data: Dict[str, str]) -> str:
        """
        Decrypt data using AES-256-CBC

        Args:
            encrypted_data: Dictionary with IV and encrypted data

        Returns:
            Decrypted data
        """
        if not self.master_key:
            raise ValueError("Master key not set. Call generate_key first.")

        # Decode IV and encrypted data
        iv = base64.b64decode(encrypted_data['iv'])
        data = base64.b64decode(encrypted_data['data'])

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()

        # Decrypt
        decrypted_data = decryptor.update(data) + decryptor.finalize()

        # Unpad data
        unpadded_data = self._unpad(decrypted_data)

        return unpadded_data.decode('utf-8')

    def _pad(self, data: bytes) -> bytes:
        """Pad data to AES block size (16 bytes)"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        """Remove padding from decrypted data"""
        padding_length = data[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
        return data[:-padding_length]

    def verify_master_password(self, master_password: str, stored_salt: bytes, stored_key_hash: str) -> bool:
        """
        Verify master password against stored hash

        Args:
            master_password: Master password to verify
            stored_salt: Stored salt
            stored_key_hash: Stored key hash

        Returns:
            True if password is correct
        """
        try:
            # Generate key from provided password
            key = self.generate_key(master_password, stored_salt)

            # Hash the key
            key_hash = hashlib.sha256(key).hexdigest()

            # Compare with stored hash
            return key_hash == stored_key_hash
        except Exception:
            return False

class PasswordGenerator:
    """
    Generates secure passwords with various complexity levels
    """

    def __init__(self):
        """Initialize password generator"""
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
        self.ambiguous = "il1Lo0O"

    def generate(self, length: int = Config.DEFAULT_PASSWORD_LENGTH,
                 use_uppercase: bool = True,
                 use_digits: bool = True,
                 use_symbols: bool = True,
                 avoid_ambiguous: bool = False) -> str:
        """
        Generate a random password

        Args:
            length: Password length
            use_uppercase: Include uppercase letters
            use_digits: Include digits
            use_symbols: Include symbols
            avoid_ambiguous: Avoid ambiguous characters

        Returns:
            Generated password
        """
        if length < Config.MIN_PASSWORD_LENGTH:
            length = Config.MIN_PASSWORD_LENGTH

        # Build character set
        chars = self.lowercase
        if use_uppercase:
            chars += self.uppercase
        if use_digits:
            chars += self.digits
        if use_symbols:
            chars += self.symbols

        # Remove ambiguous characters if requested
        if avoid_ambiguous:
            for char in self.ambiguous:
                chars = chars.replace(char, '')

        # Ensure at least one character from each required set
        password_parts = []

        # Always include lowercase
        password_parts.append(secrets.choice(self.lowercase))

        if use_uppercase:
            password_parts.append(secrets.choice(self.uppercase))

        if use_digits:
            password_parts.append(secrets.choice(self.digits))

        if use_symbols:
            password_parts.append(secrets.choice(self.symbols))

        # Fill remaining length with random characters
        remaining = length - len(password_parts)
        if remaining > 0:
            for _ in range(remaining):
                password_parts.append(secrets.choice(chars))

        # Shuffle the password
        password_list = list(password_parts)
        secrets.SystemRandom().shuffle(password_list)

        return ''.join(password_list)

    def generate_memorable(self, words: int = 4, separator: str = '-') -> str:
        """
        Generate a memorable password using random words

        Args:
            words: Number of words
            separator: Word separator

        Returns:
            Memorable password
        """
        word_list = [
            'apple', 'bicycle', 'camel', 'dragon', 'eagle', 'forest',
            'garden', 'hammer', 'island', 'jazz', 'knight', 'lion',
            'monkey', 'night', 'ocean', 'piano', 'queen', 'river',
            'soccer', 'tiger', 'umbrella', 'violet', 'water', 'xenon',
            'yellow', 'zebra', 'cloud', 'diamond', 'energy', 'flame'
        ]

        selected_words = [secrets.choice(word_list) for _ in range(words)]
        return separator.join(selected_words)

    def get_password_strength(self, password: str) -> Tuple[str, float, str]:
        """
        Calculate password strength

        Args:
            password: Password to analyze

        Returns:
            Tuple of (strength_label, score, feedback)
        """
        score = 0
        feedback = []

        # Length check
        if len(password) < 8:
            feedback.append("Too short (minimum 8 characters)")
        elif len(password) >= 12:
            score += 2
        elif len(password) >= 10:
            score += 1

        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        if has_lower:
            score += 0.5
        if has_upper:
            score += 0.5
        if has_digit:
            score += 0.5
        if has_symbol:
            score += 0.5

        # Variety feedback
        if not has_upper:
            feedback.append("Add uppercase letters")
        if not has_digit:
            feedback.append("Add numbers")
        if not has_symbol:
            feedback.append("Add symbols")

        # Common patterns check
        common_patterns = ['password', '123456', 'qwerty', 'abc123', 'admin']
        for pattern in common_patterns:
            if pattern in password.lower():
                score -= 1
                feedback.append("Contains common pattern")
                break

        # Determine strength
        if score < 2:
            strength = "Weak"
        elif score < 3:
            strength = "Fair"
        elif score < 4:
            strength = "Good"
        elif score < 4.5:
            strength = "Strong"
        else:
            strength = "Excellent"

        # Normalize score to 0-100
        score_normalized = min(100, score * 20)

        return strength, score_normalized, ", ".join(feedback) if feedback else "Good password!"

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate password against security requirements

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long"

        if len(password) > Config.MAX_PASSWORD_LENGTH:
            return False, f"Password must be at most {Config.MAX_PASSWORD_LENGTH} characters long"

        # Check for at least one uppercase, lowercase, digit
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        return True, "Valid password"

class DatabaseManager:
    """
    Manages all database operations for the password manager
    """

    def __init__(self, db_path: str = Config.DB_FILE):
        """
        Initialize database manager

        Args:
            db_path: Path to database file
        """
        self.db_path = db_path
        self.connection = None
        self.cursor = None
        self._initialize_database()

    def _initialize_database(self):
        """Create database tables if they don't exist"""
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

            self.connection = sqlite3.connect(self.db_path)
            self.cursor = self.connection.cursor()

            # Create tables
            self._create_tables()

            print("✅ Database initialized successfully")

        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            raise

    def _create_tables(self):
        """Create all necessary tables"""
        # Master password table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')

        # Password entries table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                category TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used TEXT,
                strength TEXT,
                favorite INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0
            )
        ''')

        # Security questions table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL
            )
        ''')

        # Backup history table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                size INTEGER NOT NULL
            )
        ''')

        # Audit log table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT
            )
        ''')

        self.connection.commit()

    def execute_query(self, query: str, params: tuple = (), fetch_one: bool = False,
                      fetch_all: bool = False, commit: bool = True):
        """
        Execute a database query

        Args:
            query: SQL query
            params: Query parameters
            fetch_one: Return single row
            fetch_all: Return all rows
            commit: Commit transaction

        Returns:
            Query results or None
        """
        try:
            self.cursor.execute(query, params)

            if commit:
                self.connection.commit()

            if fetch_one:
                return self.cursor.fetchone()
            elif fetch_all:
                return self.cursor.fetchall()

            return self.cursor

        except Exception as e:
            print(f"❌ Database query error: {e}")
            if commit:
                self.connection.rollback()
            return None

    def get_master_password_data(self) -> Optional[Dict]:
        """
        Get master password data

        Returns:
            Dictionary with salt and key_hash or None
        """
        result = self.execute_query(
            "SELECT salt, key_hash FROM master LIMIT 1",
            fetch_one=True
        )

        if result:
            return {
                'salt': result[0],
                'key_hash': result[1]
            }
        return None

    def save_master_password(self, salt: str, key_hash: str):
        """
        Save master password data

        Args:
            salt: Salt as base64 string
            key_hash: Key hash
        """
        now = datetime.datetime.now().isoformat()

        # Check if master exists
        if self.get_master_password_data():
            self.execute_query(
                "UPDATE master SET salt = ?, key_hash = ?, updated_at = ?",
                (salt, key_hash, now)
            )
        else:
            self.execute_query(
                "INSERT INTO master (salt, key_hash, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (salt, key_hash, now, now)
            )

    def save_password_entry(self, entry: PasswordEntry):
        """
        Save a password entry

        Args:
            entry: PasswordEntry object
        """
        query = '''
            INSERT OR REPLACE INTO passwords 
            (id, title, username, password, url, notes, category, 
             created_at, updated_at, last_used, strength, favorite, deleted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''

        self.execute_query(query, (
            entry.id,
            entry.title,
            entry.username,
            entry.password,
            entry.url,
            entry.notes,
            entry.category,
            entry.created_at,
            entry.updated_at,
            entry.last_used,
            entry.strength,
            1 if entry.favorite else 0,
            0
        ))

    def get_password_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Get a password entry by ID

        Args:
            entry_id: Entry ID

        Returns:
            PasswordEntry object or None
        """
        result = self.execute_query(
            "SELECT * FROM passwords WHERE id = ? AND deleted = 0",
            (entry_id,),
            fetch_one=True
        )

        if result:
            return self._row_to_entry(result)
        return None

    def get_all_entries(self, include_deleted: bool = False) -> List[PasswordEntry]:
        """
        Get all password entries

        Args:
            include_deleted: Include deleted entries

        Returns:
            List of PasswordEntry objects
        """
        query = "SELECT * FROM passwords"
        if not include_deleted:
            query += " WHERE deleted = 0"
        query += " ORDER BY title"

        results = self.execute_query(query, fetch_all=True)

        entries = []
        if results:
            for row in results:
                entries.append(self._row_to_entry(row))

        return entries

    def get_entries_by_category(self, category: str) -> List[PasswordEntry]:
        """
        Get entries by category

        Args:
            category: Category name

        Returns:
            List of PasswordEntry objects
        """
        results = self.execute_query(
            "SELECT * FROM passwords WHERE category = ? AND deleted = 0 ORDER BY title",
            (category,),
            fetch_all=True
        )

        entries = []
        if results:
            for row in results:
                entries.append(self._row_to_entry(row))

        return entries

    def get_favorite_entries(self) -> List[PasswordEntry]:
        """
        Get favorite entries

        Returns:
            List of PasswordEntry objects
        """
        results = self.execute_query(
            "SELECT * FROM passwords WHERE favorite = 1 AND deleted = 0 ORDER BY title",
            fetch_all=True
        )

        entries = []
        if results:
            for row in results:
                entries.append(self._row_to_entry(row))

        return entries

    def delete_entry(self, entry_id: str, permanent: bool = False):
        """
        Delete a password entry

        Args:
            entry_id: Entry ID
            permanent: Permanently delete (hard delete)
        """
        if permanent:
            self.execute_query(
                "DELETE FROM passwords WHERE id = ?",
                (entry_id,)
            )
        else:
            self.execute_query(
                "UPDATE passwords SET deleted = 1 WHERE id = ?",
                (entry_id,)
            )

    def restore_entry(self, entry_id: str):
        """
        Restore a deleted entry

        Args:
            entry_id: Entry ID
        """
        self.execute_query(
            "UPDATE passwords SET deleted = 0 WHERE id = ?",
            (entry_id,)
        )

    def toggle_favorite(self, entry_id: str, favorite: bool):
        """
        Toggle favorite status

        Args:
            entry_id: Entry ID
            favorite: New favorite status
        """
        self.execute_query(
            "UPDATE passwords SET favorite = ? WHERE id = ?",
            (1 if favorite else 0, entry_id)
        )

    def update_last_used(self, entry_id: str):
        """
        Update last used timestamp

        Args:
            entry_id: Entry ID
        """
        now = datetime.datetime.now().isoformat()
        self.execute_query(
            "UPDATE passwords SET last_used = ? WHERE id = ?",
            (now, entry_id)
        )

    def search_entries(self, query: str) -> List[PasswordEntry]:
        """
        Search entries by title, username, or URL

        Args:
            query: Search query

        Returns:
            List of matching PasswordEntry objects
        """
        search_pattern = f"%{query}%"
        results = self.execute_query(
            """
            SELECT * FROM passwords 
            WHERE (title LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ?)
            AND deleted = 0
            ORDER BY title
            """,
            (search_pattern, search_pattern, search_pattern, search_pattern),
            fetch_all=True
        )

        entries = []
        if results:
            for row in results:
                entries.append(self._row_to_entry(row))

        return entries

    def get_statistics(self) -> Dict:
        """
        Get database statistics

        Returns:
            Dictionary with statistics
        """
        # Total entries
        total = self.execute_query(
            "SELECT COUNT(*) FROM passwords WHERE deleted = 0",
            fetch_one=True
        )

        # By category
        categories = self.execute_query(
            "SELECT category, COUNT(*) FROM passwords WHERE deleted = 0 GROUP BY category",
            fetch_all=True
        )

        # Favorites
        favorites = self.execute_query(
            "SELECT COUNT(*) FROM passwords WHERE favorite = 1 AND deleted = 0",
            fetch_one=True
        )

        # Deleted
        deleted = self.execute_query(
            "SELECT COUNT(*) FROM passwords WHERE deleted = 1",
            fetch_one=True
        )

        return {
            'total': total[0] if total else 0,
            'categories': dict(categories) if categories else {},
            'favorites': favorites[0] if favorites else 0,
            'deleted': deleted[0] if deleted else 0
        }

    def _row_to_entry(self, row) -> PasswordEntry:
        """Convert database row to PasswordEntry object"""
        return PasswordEntry(
            id=row[0],
            title=row[1],
            username=row[2] or '',
            password=row[3],
            url=row[4] or '',
            notes=row[5] or '',
            category=row[6] or 'Uncategorized',
            created_at=row[7],
            updated_at=row[8],
            last_used=row[9] or '',
            strength=row[10] or 'Unknown',
            favorite=bool(row[11])
        )

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()

    def backup(self, backup_path: str = None) -> str:
        """
        Create a database backup

        Args:
            backup_path: Path for backup file

        Returns:
            Path to backup file
        """
        if backup_path is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"data/backup_{timestamp}.db"

        try:
            # Create backup
            import shutil
            shutil.copy2(self.db_path, backup_path)

            # Log backup
            entry_count = self.get_statistics()['total']
            size = os.path.getsize(backup_path)

            self.execute_query(
                "INSERT INTO backup_history (timestamp, file_path, entry_count, size) VALUES (?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(), backup_path, entry_count, size)
            )

            print(f"✅ Backup created: {backup_path}")
            return backup_path

        except Exception as e:
            print(f"❌ Backup error: {e}")
            return None

    def restore_backup(self, backup_path: str):
        """
        Restore from backup

        Args:
            backup_path: Path to backup file
        """
        try:
            import shutil
            shutil.copy2(backup_path, self.db_path)
            self._initialize_database()
            print(f"✅ Backup restored: {backup_path}")

        except Exception as e:
            print(f"❌ Restore error: {e}")

class PasswordManager:
    """
    Main Password Manager class orchestrating all functionality
    """

    def __init__(self):
        """Initialize Password Manager"""
        print("=" * 60)
        print("    🔐 PASSWORD MANAGER WITH ENCRYPTION")
        print("=" * 60)

        self.db = DatabaseManager()
        self.encryption = EncryptionEngine()
        self.generator = PasswordGenerator()

        self.is_locked = True
        self.is_authenticated = False
        self.current_user = None
        self.lock_timer = None
        self.clipboard_timer = None
        self.last_activity = time.time()

        # Session data
        self.session_entries = []
        self.current_entry = None

        print("🔐 Password Manager initialized (Locked)")

    def _check_authentication(self) -> bool:
        """Check if user is authenticated"""
        if not self.is_authenticated:
            print("\n⚠️ Please authenticate first!")
            return False

        # Check auto-lock
        if Config.AUTO_LOCK_TIMEOUT > 0:
            idle_time = time.time() - self.last_activity
            if idle_time > Config.AUTO_LOCK_TIMEOUT:
                self.lock()
                print("🔒 Auto-locked due to inactivity")
                return False

        self.last_activity = time.time()
        return True

    def _start_lock_timer(self):
        """Start auto-lock timer"""

        def lock_check():
            while self.is_authenticated:
                time.sleep(10)
                if self.is_authenticated and Config.AUTO_LOCK_TIMEOUT > 0:
                    idle_time = time.time() - self.last_activity
                    if idle_time > Config.AUTO_LOCK_TIMEOUT:
                        self.lock()
                        break

        if Config.AUTO_LOCK_TIMEOUT > 0:
            self.lock_timer = threading.Thread(target=lock_check, daemon=True)
            self.lock_timer.start()

    def _clear_clipboard(self, text: str):
        """Clear clipboard after timeout"""
        if not CLIPBOARD_AVAILABLE:
            return

        def clear():
            time.sleep(Config.CLIPBOARD_CLEAR_TIMEOUT)
            current = pyperclip.paste()
            if current == text:
                pyperclip.copy("")
                print("🧹 Clipboard cleared")

        self.clipboard_timer = threading.Thread(target=clear, daemon=True)
        self.clipboard_timer.start()

    def setup_master_password(self):
        """
        Setup master password (first time setup)
        """
        print("\n🔑 SETUP MASTER PASSWORD")
        print("-" * 40)
        print("This is the first time setup. Please create a master password.")
        print("This password will be used to unlock your password vault.")
        print("⚠️ WARNING: If you forget this password, your data will be lost!")
        print("-" * 40)

        # Check if master password already exists
        if self.db.get_master_password_data():
            print("⚠️ Master password already set.")
            return False

        # Create security questions
        print("\nSecurity Questions (for recovery):")
        answers = {}

        for i, question in enumerate(Config.SECURITY_QUESTIONS[:3], 1):
            print(f"\n{i}. {question}")
            answer = getpass.getpass("Answer: ")
            answers[question] = answer

        # Get master password
        while True:
            password = getpass.getpass("\nEnter master password: ")
            confirm = getpass.getpass("Confirm master password: ")

            if password != confirm:
                print("❌ Passwords do not match. Try again.")
                continue

            # Validate password strength
            is_valid, message = self.generator.validate_password(password)
            if not is_valid:
                print(f"❌ {message}")
                continue

            break

        # Generate salt and key
        salt = os.urandom(Config.SALT_SIZE)
        key = self.encryption.generate_key(password, salt)
        key_hash = hashlib.sha256(key).hexdigest()

        # Save master password data
        self.db.save_master_password(
            base64.b64encode(salt).decode('utf-8'),
            key_hash
        )

        # Save security questions (encrypted)
        for question, answer in answers.items():
            encrypted_answer = self.encryption.encrypt(answer)
            self.db.execute_query(
                "INSERT INTO security_questions (question, answer) VALUES (?, ?)",
                (question, json.dumps(encrypted_answer))
            )

        # Authenticate
        self.is_authenticated = True
        self.is_locked = False

        print("\n✅ Master password setup complete!")
        print("🔓 You are now authenticated.")

        self._start_lock_timer()
        return True

    def authenticate(self):
        """
        Authenticate with master password
        """
        if self.is_authenticated:
            print("✅ Already authenticated")
            return True

        # Get master password data
        master_data = self.db.get_master_password_data()
        if not master_data:
            print("⚠️ No master password found. Please set up first.")
            return self.setup_master_password()

        print("\n🔐 AUTHENTICATION")
        print("-" * 40)

        attempts = 0
        max_attempts = 3

        while attempts < max_attempts:
            password = getpass.getpass("Enter master password: ")

            # Decode salt
            salt = base64.b64decode(master_data['salt'])
            key_hash = master_data['key_hash']

            # Verify password
            if self.encryption.verify_master_password(password, salt, key_hash):
                # Authentication successful
                self.is_authenticated = True
                self.is_locked = False
                self.last_activity = time.time()

                print("✅ Authentication successful!")
                print("🔓 Vault unlocked.")

                self._start_lock_timer()
                return True
            else:
                attempts += 1
                remaining = max_attempts - attempts
                print(f"❌ Invalid password. {remaining} attempts remaining.")

        print("❌ Too many failed attempts. Locked.")
        return False

    def lock(self):
        """Lock the password manager"""
        self.is_authenticated = False
        self.is_locked = True
        self.master_key = None
        print("🔒 Password Manager locked.")

    def unlock(self):
        """Unlock the password manager"""
        return self.authenticate()

    def add_entry(self, title: str, username: str, password: str,
                  url: str = "", notes: str = "", category: str = "General") -> bool:
        """
        Add a new password entry

        Args:
            title: Entry title
            username: Username
            password: Password (plain text)
            url: Website URL
            notes: Additional notes
            category: Category

        Returns:
            True if added successfully
        """
        if not self._check_authentication():
            return False

        # Validate password
        is_valid, message = self.generator.validate_password(password)
        if not is_valid:
            print(f"❌ {message}")
            return False

        # Generate unique ID
        entry_id = secrets.token_urlsafe(16)

        # Encrypt password
        encrypted_password = self.encryption.encrypt(password)

        # Calculate password strength
        strength, score, feedback = self.generator.get_password_strength(password)

        # Create entry
        now = datetime.datetime.now().isoformat()
        entry = PasswordEntry(
            id=entry_id,
            title=title,
            username=username,
            password=json.dumps(encrypted_password),
            url=url,
            notes=notes,
            category=category,
            created_at=now,
            updated_at=now,
            last_used=now,
            strength=strength,
            favorite=False
        )

        # Save to database
        self.db.save_password_entry(entry)

        print(f"✅ Password entry added: {title}")
        return True

    def get_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Get a password entry with decrypted password

        Args:
            entry_id: Entry ID

        Returns:
            PasswordEntry object with decrypted password
        """
        if not self._check_authentication():
            return None

        entry = self.db.get_password_entry(entry_id)
        if entry:
            # Decrypt password
            encrypted_data = json.loads(entry.password)
            entry.password = self.encryption.decrypt(encrypted_data)

            # Update last used
            self.db.update_last_used(entry_id)

        return entry

    def get_all_entries(self) -> List[PasswordEntry]:
        """
        Get all password entries (decrypted)

        Returns:
            List of PasswordEntry objects with decrypted passwords
        """
        if not self._check_authentication():
            return []

        entries = self.db.get_all_entries()

        # Decrypt passwords
        for entry in entries:
            encrypted_data = json.loads(entry.password)
            entry.password = self.encryption.decrypt(encrypted_data)

        return entries

    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """
        Update a password entry

        Args:
            entry_id: Entry ID
            kwargs: Fields to update

        Returns:
            True if updated successfully
        """
        if not self._check_authentication():
            return False

        # Get current entry
        entry = self.db.get_password_entry(entry_id)
        if not entry:
            print("❌ Entry not found")
            return False

        # Update fields
        updated = False

        if 'title' in kwargs:
            entry.title = kwargs['title']
            updated = True

        if 'username' in kwargs:
            entry.username = kwargs['username']
            updated = True

        if 'password' in kwargs:
            # Validate password
            is_valid, message = self.generator.validate_password(kwargs['password'])
            if not is_valid:
                print(f"❌ {message}")
                return False

            # Encrypt new password
            encrypted_password = self.encryption.encrypt(kwargs['password'])
            entry.password = json.dumps(encrypted_password)

            # Update strength
            strength, score, feedback = self.generator.get_password_strength(kwargs['password'])
            entry.strength = strength

            updated = True

        if 'url' in kwargs:
            entry.url = kwargs['url']
            updated = True

        if 'notes' in kwargs:
            entry.notes = kwargs['notes']
            updated = True

        if 'category' in kwargs:
            entry.category = kwargs['category']
            updated = True

        if updated:
            entry.updated_at = datetime.datetime.now().isoformat()
            self.db.save_password_entry(entry)
            print(f"✅ Entry updated: {entry.title}")

        return updated

    def delete_entry(self, entry_id: str, permanent: bool = False) -> bool:
        """
        Delete a password entry

        Args:
            entry_id: Entry ID
            permanent: Permanently delete

        Returns:
            True if deleted successfully
        """
        if not self._check_authentication():
            return False

        entry = self.db.get_password_entry(entry_id)
        if not entry:
            print("❌ Entry not found")
            return False

        self.db.delete_entry(entry_id, permanent)

        action = "permanently" if permanent else "soft"
        print(f"✅ Entry {action} deleted: {entry.title}")
        return True

    def search_entries(self, query: str) -> List[PasswordEntry]:
        """
        Search for password entries

        Args:
            query: Search query

        Returns:
            List of matching PasswordEntry objects (decrypted)
        """
        if not self._check_authentication():
            return []

        entries = self.db.search_entries(query)

        # Decrypt passwords
        for entry in entries:
            encrypted_data = json.loads(entry.password)
            entry.password = self.encryption.decrypt(encrypted_data)

        return entries

    def toggle_favorite(self, entry_id: str) -> bool:
        """
        Toggle favorite status

        Args:
            entry_id: Entry ID

        Returns:
            True if toggled successfully
        """
        if not self._check_authentication():
            return False

        entry = self.db.get_password_entry(entry_id)
        if not entry:
            print("❌ Entry not found")
            return False

        new_status = not entry.favorite
        self.db.toggle_favorite(entry_id, new_status)

        status = "added to" if new_status else "removed from"
        print(f"✅ Entry {status} favorites: {entry.title}")
        return True

    def generate_password(self, length: int = Config.DEFAULT_PASSWORD_LENGTH,
                          include_uppercase: bool = True,
                          include_digits: bool = True,
                          include_symbols: bool = True,
                          avoid_ambiguous: bool = False) -> str:
        """
        Generate a random password

        Returns:
            Generated password
        """
        return self.generator.generate(length, include_uppercase,
                                       include_digits, include_symbols,
                                       avoid_ambiguous)

    def generate_memorable_password(self, words: int = 4) -> str:
        """
        Generate a memorable password

        Returns:
            Memorable password
        """
        return self.generator.generate_memorable(words)

    def analyze_password(self, password: str) -> Dict:
        """
        Analyze password strength

        Returns:
            Dictionary with strength analysis
        """
        strength, score, feedback = self.generator.get_password_strength(password)

        return {
            'strength': strength,
            'score': score,
            'feedback': feedback,
            'length': len(password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_lowercase': any(c.islower() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_symbols': any(not c.isalnum() for c in password)
        }

    def export_to_json(self, file_path: str = Config.EXPORT_FILE) -> bool:
        """
        Export all entries to JSON file

        Args:
            file_path: Output file path

        Returns:
            True if exported successfully
        """
        if not self._check_authentication():
            return False

        entries = self.get_all_entries()

        # Prepare data for export
        export_data = {
            'export_date': datetime.datetime.now().isoformat(),
            'count': len(entries),
            'entries': []
        }

        for entry in entries:
            export_data['entries'].append(entry.to_dict())

        # Save to file
        try:
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            print(f"✅ Exported {len(entries)} entries to: {file_path}")
            return True

        except Exception as e:
            print(f"❌ Export error: {e}")
            return False

    def import_from_json(self, file_path: str) -> bool:
        """
        Import entries from JSON file

        Args:
            file_path: Input file path

        Returns:
            True if imported successfully
        """
        if not self._check_authentication():
            return False

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            imported = 0
            for entry_data in data.get('entries', []):
                # Create new entry
                password = entry_data.get('password', '')
                title = entry_data.get('title', 'Imported Entry')
                username = entry_data.get('username', '')
                url = entry_data.get('url', '')
                notes = entry_data.get('notes', '')
                category = entry_data.get('category', 'Imported')

                if self.add_entry(title, username, password, url, notes, category):
                    imported += 1

            print(f"✅ Imported {imported} entries from: {file_path}")
            return True

        except Exception as e:
            print(f"❌ Import error: {e}")
            return False

    def copy_to_clipboard(self, text: str) -> bool:
        """
        Copy text to clipboard with auto-clear

        Args:
            text: Text to copy

        Returns:
            True if copied successfully
        """
        if not CLIPBOARD_AVAILABLE:
            print("⚠️ Clipboard module not available")
            return False

        try:
            pyperclip.copy(text)
            print("📋 Copied to clipboard (will clear in 30 seconds)")
            self._clear_clipboard(text)
            return True

        except Exception as e:
            print(f"❌ Clipboard error: {e}")
            return False

    def get_statistics(self) -> Dict:
        """
        Get password manager statistics

        Returns:
            Dictionary with statistics
        """
        if not self._check_authentication():
            return {}

        stats = self.db.get_statistics()

        # Add additional stats
        stats['vault_size'] = os.path.getsize(self.db.db_path) if os.path.exists(self.db.db_path) else 0

        return stats

    def backup_vault(self) -> str:
        """
        Create a backup of the vault

        Returns:
            Backup file path
        """
        if not self._check_authentication():
            return None

        return self.db.backup()

    def restore_vault(self, backup_path: str) -> bool:
        """
        Restore vault from backup

        Args:
            backup_path: Path to backup file

        Returns:
            True if restored successfully
        """
        if not self._check_authentication():
            return False

        self.db.restore_backup(backup_path)
        return True

    def check_password_breach(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been breached using Have I Been Pwned API

        Args:
            password: Password to check

        Returns:
            Tuple of (is_breached, count)
        """
        try:
            import requests
            import hashlib

            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Check against API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                # Parse response
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(':')[1])
                        print(f"⚠️ Password has been compromised {count} times!")
                        return True, count

                print("✅ Password not found in breach database.")
                return False, 0
            else:
                print("❌ Could not check breach status.")
                return False, -1

        except ImportError:
            print("⚠️ requests module not installed. Cannot check breaches.")
            return False, -1
        except Exception as e:
            print(f"❌ Breach check error: {e}")
            return False, -1

    def clean_database(self) -> bool:
        """
        Clean and optimize database

        Returns:
            True if cleaned successfully
        """
        if not self._check_authentication():
            return False

        try:
            self.db.execute_query("VACUUM", commit=False)
            self.db.connection.commit()
            print("✅ Database cleaned and optimized")
            return True
        except Exception as e:
            print(f"❌ Database cleaning error: {e}")
            return False

    def main_menu(self):
        """
        Display main menu and handle user input
        """
        while True:
            print("\n" + "=" * 60)
            print("    🔐 PASSWORD MANAGER")
            print("=" * 60)
            print(f"Status: {'🔓 Unlocked' if self.is_authenticated else '🔒 Locked'}")
            print("-" * 60)
            print("1. Add Entry")
            print("2. View Entries")
            print("3. Search Entries")
            print("4. Generate Password")
            print("5. Analyze Password")
            print("6. Export/Import Data")
            print("7. Backup & Restore")
            print("8. Statistics")
            print("9. Settings")
            print("10. Lock Vault")
            print("11. Clean Database")
            print("12. Exit")
            print("-" * 60)

            choice = input("Enter your choice: ").strip()

            if choice == '1':
                self.menu_add_entry()
            elif choice == '2':
                self.menu_view_entries()
            elif choice == '3':
                self.menu_search_entries()
            elif choice == '4':
                self.menu_generate_password()
            elif choice == '5':
                self.menu_analyze_password()
            elif choice == '6':
                self.menu_import_export()
            elif choice == '7':
                self.menu_backup_restore()
            elif choice == '8':
                self.menu_statistics()
            elif choice == '9':
                self.menu_settings()
            elif choice == '10':
                self.lock()
            elif choice == '11':
                self.clean_database()
            elif choice == '12':
                if self.is_authenticated:
                    self.lock()
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.")

    def menu_add_entry(self):
        """Add a new password entry"""
        if not self.is_authenticated:
            self.authenticate()
            if not self.is_authenticated:
                return

        print("\n📝 ADD PASSWORD ENTRY")
        print("-" * 40)

        title = input("Title: ").strip()
        if not title:
            print("❌ Title is required")
            return

        username = input("Username: ").strip()
        url = input("URL (optional): ").strip()
        category = input("Category (default: General): ").strip() or "General"
        notes = input("Notes (optional): ").strip()

        print("\nChoose password option:")
        print("1. Enter password manually")
        print("2. Generate password")
        print("3. Generate memorable password")

        pw_choice = input("Choice: ").strip()

        if pw_choice == '2':
            length = input("Password length (default 16): ").strip()
            length = int(length) if length else 16
            password = self.generate_password(length)
            print(f"Generated password: {password}")

        elif pw_choice == '3':
            words = input("Number of words (default 4): ").strip()
            words = int(words) if words else 4
            password = self.generate_memorable_password(words)
            print(f"Generated password: {password}")

        else:
            password = getpass.getpass("Enter password: ")
            confirm = getpass.getpass("Confirm password: ")

            if password != confirm:
                print("❌ Passwords do not match")
                return

        self.add_entry(title, username, password, url, notes, category)

    def menu_view_entries(self):
        """View all password entries"""
        if not self.is_authenticated:
            self.authenticate()
            if not self.is_authenticated:
                return

        entries = self.get_all_entries()

        if not entries:
            print("📭 No entries found")
            return

        print(f"\n📋 PASSWORD ENTRIES ({len(entries)})")
        print("-" * 40)

        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.title}")
            print(f"   Username: {entry.username}")
            print(f"   Category: {entry.category}")
            print(f"   Strength: {entry.strength}")
            print(f"   {'⭐ Favorite' if entry.favorite else ''}")
            print("-" * 40)

        # View entry details
        choice = input("Enter number to view details (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(entries):
                self.menu_view_entry_details(entries[idx].id)
        except ValueError:
            pass

    def menu_view_entry_details(self, entry_id: str):
        """View detailed entry information"""
        entry = self.get_entry(entry_id)
        if not entry:
            print("❌ Entry not found")
            return

        print("\n📄 ENTRY DETAILS")
        print("=" * 40)
        print(f"Title: {entry.title}")
        print(f"Username: {entry.username}")
        print(f"Password: {entry.password}")
        print(f"URL: {entry.url or 'N/A'}")
        print(f"Category: {entry.category}")
        print(f"Notes: {entry.notes or 'N/A'}")
        print(f"Strength: {entry.strength}")
        print(f"Created: {entry.created_at}")
        print(f"Updated: {entry.updated_at}")
        print(f"Last Used: {entry.last_used or 'Never'}")
        print(f"Favorite: {'⭐ Yes' if entry.favorite else 'No'}")
        print("=" * 40)

        print("\nOptions:")
        print("1. Copy password to clipboard")
        print("2. Copy username to clipboard")
        print("3. Toggle favorite")
        print("4. Edit entry")
        print("5. Delete entry")
        print("6. Back")

        choice = input("Choice: ").strip()

        if choice == '1':
            self.copy_to_clipboard(entry.password)
        elif choice == '2':
            self.copy_to_clipboard(entry.username)
        elif choice == '3':
            self.toggle_favorite(entry_id)
        elif choice == '4':
            self.menu_edit_entry(entry_id)
        elif choice == '5':
            confirm = input("Are you sure you want to delete this entry? (y/n): ").lower()
            if confirm == 'y':
                self.delete_entry(entry_id)

    def menu_edit_entry(self, entry_id: str):
        """Edit a password entry"""
        if not self._check_authentication():
            return

        entry = self.db.get_password_entry(entry_id)
        if not entry:
            print("❌ Entry not found")
            return

        print("\n✏️ EDIT ENTRY")
        print("-" * 40)
        print(f"Current title: {entry.title}")
        print(f"Current username: {entry.username}")
        print(f"Current URL: {entry.url}")
        print(f"Current category: {entry.category}")
        print("(Leave blank to keep current value)")

        title = input("New title: ").strip()
        username = input("New username: ").strip()
        url = input("New URL: ").strip()
        category = input("New category: ").strip()

        update_data = {}
        if title:
            update_data['title'] = title
        if username:
            update_data['username'] = username
        if url:
            update_data['url'] = url
        if category:
            update_data['category'] = category

        change_password = input("Change password? (y/n): ").lower()
        if change_password == 'y':
            password = getpass.getpass("New password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password == confirm:
                update_data['password'] = password
            else:
                print("❌ Passwords do not match")

        if update_data:
            self.update_entry(entry_id, **update_data)
        else:
            print("No changes made")

    def menu_search_entries(self):
        """Search for password entries"""
        if not self.is_authenticated:
            self.authenticate()
            if not self.is_authenticated:
                return

        query = input("\n🔍 Search query: ").strip()
        if not query:
            return

        entries = self.search_entries(query)

        if not entries:
            print("No entries found")
            return

        print(f"\n📋 SEARCH RESULTS ({len(entries)})")
        print("-" * 40)

        for i, entry in enumerate(entries, 1):
            print(f"{i}. {entry.title}")
            print(f"   Username: {entry.username}")
            print(f"   Category: {entry.category}")
            print("-" * 40)

        # View entry details
        choice = input("Enter number to view details (or 'q' to quit): ").strip()
        if choice.lower() == 'q':
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(entries):
                self.menu_view_entry_details(entries[idx].id)
        except ValueError:
            pass

    def menu_generate_password(self):
        """Generate a password"""
        print("\n🔑 PASSWORD GENERATOR")
        print("-" * 40)

        print("Options:")
        print("1. Standard password")
        print("2. Memorable password")

        choice = input("Choice: ").strip()

        if choice == '1':
            length = input("Password length (default 16): ").strip()
            length = int(length) if length else 16

            include_uppercase = input("Include uppercase? (y/n): ").lower() == 'y'
            include_digits = input("Include digits? (y/n): ").lower() == 'y'
            include_symbols = input("Include symbols? (y/n): ").lower() == 'y'
            avoid_ambiguous = input("Avoid ambiguous characters? (y/n): ").lower() == 'y'

            password = self.generate_password(length, include_uppercase,
                                              include_digits, include_symbols,
                                              avoid_ambiguous)

        elif choice == '2':
            words = input("Number of words (default 4): ").strip()
            words = int(words) if words else 4
            password = self.generate_memorable_password(words)

        else:
            print("Invalid choice")
            return

        print(f"\nGenerated password: {password}")

        # Analyze password
        analysis = self.analyze_password(password)
        print(f"Strength: {analysis['strength']} ({analysis['score']:.0f}%)")
        print(f"Feedback: {analysis['feedback']}")

        copy = input("Copy to clipboard? (y/n): ").lower()
        if copy == 'y':
            self.copy_to_clipboard(password)

    def menu_analyze_password(self):
        """Analyze password strength"""
        print("\n🔍 PASSWORD ANALYSIS")
        print("-" * 40)

        password = getpass.getpass("Enter password to analyze: ")

        analysis = self.analyze_password(password)

        print("\n📊 ANALYSIS RESULTS")
        print("=" * 40)
        print(f"Strength: {analysis['strength']} ({analysis['score']:.0f}%)")
        print(f"Length: {analysis['length']} characters")
        print(f"Uppercase: {'✅' if analysis['has_uppercase'] else '❌'}")
        print(f"Lowercase: {'✅' if analysis['has_lowercase'] else '❌'}")
        print(f"Digits: {'✅' if analysis['has_digits'] else '❌'}")
        print(f"Symbols: {'✅' if analysis['has_symbols'] else '❌'}")
        print(f"\nFeedback: {analysis['feedback']}")
        print("=" * 40)

        # Check for breaches
        if len(password) >= 8:
            check = input("Check if password has been breached? (y/n): ").lower()
            if check == 'y':
                self.check_password_breach(password)

    def menu_import_export(self):
        """Import and export data"""
        print("\n📦 IMPORT / EXPORT")
        print("-" * 40)
        print("1. Export to JSON")
        print("2. Import from JSON")

        choice = input("Choice: ").strip()

        if choice == '1':
            file_path = input("Export file path (default: data/export.json): ").strip()
            if not file_path:
                file_path = Config.EXPORT_FILE
            self.export_to_json(file_path)

        elif choice == '2':
            file_path = input("Import file path: ").strip()
            if file_path:
                self.import_from_json(file_path)

    def menu_backup_restore(self):
        """Backup and restore vault"""
        print("\n💾 BACKUP & RESTORE")
        print("-" * 40)
        print("1. Create backup")
        print("2. Restore from backup")

        choice = input("Choice: ").strip()

        if choice == '1':
            self.backup_vault()
        elif choice == '2':
            file_path = input("Backup file path: ").strip()
            if file_path:
                self.restore_vault(file_path)

    def menu_statistics(self):
        """Display statistics"""
        if not self.is_authenticated:
            self.authenticate()
            if not self.is_authenticated:
                return

        stats = self.get_statistics()

        print("\n📊 VAULT STATISTICS")
        print("=" * 40)
        print(f"Total entries: {stats.get('total', 0)}")
        print(f"Favorites: {stats.get('favorites', 0)}")
        print(f"Deleted entries: {stats.get('deleted', 0)}")
        print(f"Vault size: {stats.get('vault_size', 0) / 1024:.2f} KB")

        print("\nCategories:")
        categories = stats.get('categories', {})
        if categories:
            for category, count in sorted(categories.items(),
                                          key=lambda x: x[1], reverse=True):
                print(f"  {category}: {count}")
        else:
            print("  No categories")
        print("=" * 40)

    def menu_settings(self):
        """Display settings"""
        print("\n⚙️ SETTINGS")
        print("=" * 40)
        print(f"Auto-lock timeout: {Config.AUTO_LOCK_TIMEOUT} seconds")
        print(f"Clipboard clear timeout: {Config.CLIPBOARD_CLEAR_TIMEOUT} seconds")
        print(f"Minimum password length: {Config.MIN_PASSWORD_LENGTH}")
        print(f"Maximum password length: {Config.MAX_PASSWORD_LENGTH}")
        print(f"Default password length: {Config.DEFAULT_PASSWORD_LENGTH}")
        print("=" * 40)

        print("\nOptions:")
        print("1. Change auto-lock timeout")
        print("2. Change clipboard clear timeout")
        print("3. Change default password length")

        choice = input("Choice: ").strip()

        if choice == '1':
            timeout = input("New timeout (seconds, 0 to disable): ").strip()
            try:
                Config.AUTO_LOCK_TIMEOUT = int(timeout)
                print(f"✅ Auto-lock timeout set to {Config.AUTO_LOCK_TIMEOUT} seconds")
            except ValueError:
                print("❌ Invalid value")

        elif choice == '2':
            timeout = input("New clipboard clear timeout (seconds): ").strip()
            try:
                Config.CLIPBOARD_CLEAR_TIMEOUT = int(timeout)
                print(f"✅ Clipboard clear timeout set to {Config.CLIPBOARD_CLEAR_TIMEOUT} seconds")
            except ValueError:
                print("❌ Invalid value")

        elif choice == '3':
            length = input("New default password length: ").strip()
            try:
                Config.DEFAULT_PASSWORD_LENGTH = int(length)
                print(f"✅ Default password length set to {Config.DEFAULT_PASSWORD_LENGTH}")
            except ValueError:
                print("❌ Invalid value")


def main():
    """Main function to start the Password Manager"""
    try:
        # Create required directories
        os.makedirs("data", exist_ok=True)
        os.makedirs("logs", exist_ok=True)

        # Initialize password manager
        manager = PasswordManager()

        # Authenticate or setup
        if manager.db.get_master_password_data():
            # Check if locked
            if manager.is_locked:
                manager.authenticate()
        else:
            manager.setup_master_password()

        # Start main menu if authenticated
        if manager.is_authenticated:
            manager.main_menu()

    except KeyboardInterrupt:
        print("\n\n👋 Program terminated by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()