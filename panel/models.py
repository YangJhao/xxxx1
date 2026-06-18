"""SQLite data models for 42IPwin."""
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "panel.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

Base = declarative_base()
engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)

PROTOCOL_TYPES = ["socks5", "http", "ss", "vless", "trojan", "hysteria2"]
SS_METHODS = [
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-ietf-poly1305",
    "aes-256-cfb",
    "aes-128-cfb",
    "rc4-md5",
]


class Line(Base):
    __tablename__ = "lines"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    public_ip = Column(String(45), nullable=False)
    internal_ip = Column(String(45), default="0.0.0.0")
    socks_port = Column(Integer, nullable=False, unique=True)
    http_port = Column(Integer, nullable=True)
    ss_port = Column(Integer, nullable=True)
    status = Column(Integer, default=1)
    note = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("ProxyUser", back_populates="line", cascade="all, delete-orphan")

    def get_port_by_protocol(self, proto: str) -> int:
        proto = (proto or "socks5").lower()
        if proto == "http":
            return self.http_port or (self.socks_port + 10)
        if proto == "ss":
            return self.ss_port or (self.socks_port + 20)
        if proto == "vless":
            return 13000 + self.id
        if proto == "trojan":
            return 14000 + self.id
        if proto == "hysteria2":
            return 15000 + self.id
        return self.socks_port

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "public_ip": self.public_ip,
            "internal_ip": self.internal_ip,
            "socks_port": self.socks_port,
            "http_port": self.http_port,
            "ss_port": self.ss_port,
            "vless_port": self.get_port_by_protocol("vless"),
            "trojan_port": self.get_port_by_protocol("trojan"),
            "hysteria2_port": self.get_port_by_protocol("hysteria2"),
            "status": self.status,
            "note": self.note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "user_count": len([u for u in self.users if u.status == 1]),
        }


class ProxyUser(Base):
    __tablename__ = "proxy_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False)
    password = Column(String(128), nullable=False)
    ss_password = Column(String(128), nullable=True)
    line_id = Column(Integer, ForeignKey("lines.id"), nullable=False)
    protocol = Column(String(16), default="socks5")
    listen_port = Column(Integer, nullable=True)
    ss_method = Column(String(32), nullable=True)
    owner_name = Column(String(96), nullable=True)
    project_name = Column(String(96), nullable=True)
    speed_limit = Column(String(32), nullable=True)
    traffic_limit = Column(String(32), nullable=True)
    status = Column(Integer, default=1)
    expire_at = Column(DateTime, nullable=True)
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)
    note = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    line = relationship("Line", back_populates="users")
    traffic_logs = relationship("TrafficLog", back_populates="user", cascade="all, delete-orphan")

    def _port(self) -> int:
        return self.listen_port or self.line.get_port_by_protocol(self.protocol)

    def get_connection_info(self) -> dict:
        if not self.line:
            return {}

        proto = self.protocol or "socks5"
        host = self.line.public_ip
        port = self._port()
        ss_password = self.ss_password or self.password
        ss_method = self.ss_method or "aes-256-gcm"
        expire_date = self.expire_at.date().isoformat() if self.expire_at else ""

        if proto == "ss":
            link = f"ss://{ss_method}:{ss_password}@{host}:{port}#{self.username}"
            field = f"{host}|{port}|{ss_method}|{ss_password}"
            inbound_user = ss_method
            inbound_password = ss_password
        elif proto == "vless":
            link = f"vless://{self.password}@{host}:{port}?encryption=none&type=tcp#{self.username}"
            field = f"{host}|{port}|{self.password}|{expire_date}"
            inbound_user = self.username
            inbound_password = self.password
        elif proto == "trojan":
            link = f"trojan://{self.password}@{host}:{port}?security=tls&allowInsecure=1&sni={host}#{self.username}"
            field = f"{host}|{port}|{self.username}|{self.password}|{expire_date}"
            inbound_user = self.username
            inbound_password = self.password
        elif proto == "hysteria2":
            link = f"hysteria2://{self.password}@{host}:{port}?insecure=1&sni={host}#{self.username}"
            field = f"{host}|{port}|{self.username}|{self.password}|{expire_date}"
            inbound_user = self.username
            inbound_password = self.password
        elif proto == "http":
            link = f"http://{self.username}:{self.password}@{host}:{port}"
            field = f"{host}|{port}|{self.username}|{self.password}"
            inbound_user = self.username
            inbound_password = self.password
        else:
            link = f"socks5://{self.username}:{self.password}@{host}:{port}"
            field = f"{host}|{port}|{self.username}|{self.password}"
            inbound_user = self.username
            inbound_password = self.password

        return {
            "protocol": proto,
            "server": host,
            "port": port,
            "username": inbound_user,
            "password": inbound_password,
            "method": ss_method if proto == "ss" else None,
            "uri": link,
            "field": field,
            "expire_at": self.expire_at.isoformat() if self.expire_at else None,
            "inbound": {
                "protocol": proto,
                "address": host,
                "port": port,
                "username": inbound_user,
                "password": inbound_password,
                "udp": proto in ("socks5", "ss", "hysteria2"),
            },
            "outbound": {
                "protocol": "freedom",
                "target": "直连",
                "username": "-",
                "password": "-",
                "outbound_ip": host,
            },
        }

    def to_dict(self, hide_password=False):
        d = {
            "id": self.id,
            "username": self.username,
            "line_id": self.line_id,
            "line_name": self.line.name if self.line else None,
            "line_ip": self.line.public_ip if self.line else None,
            "socks_port": self.line.socks_port if self.line else None,
            "http_port": self.line.http_port if self.line else None,
            "ss_port": self.line.ss_port if self.line else None,
            "vless_port": self.line.get_port_by_protocol("vless") if self.line else None,
            "trojan_port": self.line.get_port_by_protocol("trojan") if self.line else None,
            "hysteria2_port": self.line.get_port_by_protocol("hysteria2") if self.line else None,
            "protocol": self.protocol,
            "listen_port": self._port() if self.line else self.listen_port,
            "ss_method": self.ss_method,
            "owner_name": self.owner_name,
            "project_name": self.project_name,
            "speed_limit": self.speed_limit,
            "traffic_limit": self.traffic_limit,
            "status": self.status,
            "expire_at": self.expire_at.isoformat() if self.expire_at else None,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "note": self.note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if not hide_password:
            d["password"] = self.password
            d["ss_password"] = self.ss_password
        return d


class TrafficLog(Base):
    __tablename__ = "traffic_log"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("proxy_users.id"), nullable=False)
    line_id = Column(Integer, ForeignKey("lines.id"), nullable=False)
    hour = Column(String(13), nullable=False)
    bytes_in = Column(Integer, default=0)
    bytes_out = Column(Integer, default=0)

    user = relationship("ProxyUser", back_populates="traffic_logs")


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False, unique=True)
    display_name = Column(String(64), default="")
    role = Column(String(32), default="普通用户")
    permissions = Column(Text, default="")
    status = Column(Integer, default=1)
    password_hash = Column(String(256), nullable=False)
    is_super = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name or self.username,
            "role": "超级管理员" if self.is_super else (self.role or "普通用户"),
            "permissions": self.permissions or "",
            "status": self.status,
            "is_super": self.is_super,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(96), nullable=False)
    note = Column(Text, default="")
    status = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "note": self.note or "-",
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NodeCustomer(Base):
    __tablename__ = "node_customers"

    id = Column(Integer, primary_key=True)
    name = Column(String(96), nullable=False, unique=True)
    note = Column(Text, default="")
    status = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "note": self.note or "-",
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Plan(Base):
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True)
    name = Column(String(96), nullable=False, unique=True)
    bandwidth = Column(String(32), default="")
    traffic = Column(String(32), default="")
    days = Column(Integer, default=30)
    note = Column(Text, default="")
    status = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "bandwidth": self.bandwidth or "-",
            "traffic": self.traffic or "-",
            "days": self.days,
            "note": self.note or "-",
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class OperationLog(Base):
    __tablename__ = "operation_logs"

    id = Column(Integer, primary_key=True)
    operator = Column(String(64), default="")
    module = Column(String(64), default="")
    action = Column(String(128), default="")
    detail = Column(Text, default="")
    ip = Column(String(64), default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "operator": self.operator or "-",
            "module": self.module or "-",
            "action": self.action or "-",
            "detail": self.detail or "-",
            "ip": self.ip or "-",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def _migrate_db():
    alter_lines = [
        ("http_port", "INTEGER"),
        ("ss_port", "INTEGER"),
    ]
    alter_proxy = [
        ("ss_password", "TEXT"),
        ("protocol", "TEXT DEFAULT 'socks5'"),
        ("listen_port", "INTEGER"),
        ("ss_method", "TEXT"),
        ("owner_name", "TEXT"),
        ("project_name", "TEXT"),
        ("speed_limit", "TEXT"),
        ("traffic_limit", "TEXT"),
    ]
    alter_admin = [
        ("display_name", "TEXT"),
        ("role", "TEXT DEFAULT '普通用户'"),
        ("permissions", "TEXT"),
        ("status", "INTEGER DEFAULT 1"),
    ]
    from sqlalchemy import text

    with engine.connect() as conn:
        for col_name, col_type in alter_proxy:
            try:
                conn.execute(text(f"ALTER TABLE proxy_users ADD COLUMN {col_name} {col_type}"))
                print(f"[migrate] + proxy_users.{col_name}")
            except Exception as e:
                msg = str(e).lower()
                if "duplicate" not in msg and "already" not in msg and "exist" not in msg:
                    print(f"[migrate] ! proxy_users.{col_name}: {e}")
        for col_name, col_type in alter_lines:
            try:
                conn.execute(text(f"ALTER TABLE lines ADD COLUMN {col_name} {col_type}"))
                print(f"[migrate] + lines.{col_name}")
            except Exception as e:
                msg = str(e).lower()
                if "duplicate" not in msg and "already" not in msg and "exist" not in msg:
                    print(f"[migrate] ! lines.{col_name}: {e}")
        for col_name, col_type in alter_admin:
            try:
                conn.execute(text(f"ALTER TABLE admin_users ADD COLUMN {col_name} {col_type}"))
                print(f"[migrate] + admin_users.{col_name}")
            except Exception as e:
                msg = str(e).lower()
                if "duplicate" not in msg and "already" not in msg and "exist" not in msg:
                    print(f"[migrate] ! admin_users.{col_name}: {e}")

    # Older installs had global UNIQUE indexes on proxy_users.username or
    # proxy_users.listen_port. Rebuild once so accounts and ports can be reused on
    # different lines/IPs.
    with engine.begin() as conn:
        indexes = conn.execute(text("PRAGMA index_list(proxy_users)")).fetchall()
        has_username_unique = False
        has_listen_port_unique = False
        for idx in indexes:
            idx_name = idx[1]
            is_unique = bool(idx[2])
            if not is_unique:
                continue
            cols = conn.execute(text(f"PRAGMA index_info({idx_name})")).fetchall()
            if [c[2] for c in cols] == ["username"]:
                has_username_unique = True
            if [c[2] for c in cols] == ["listen_port"]:
                has_listen_port_unique = True
        if has_username_unique or has_listen_port_unique:
            conn.execute(text("""
                CREATE TABLE proxy_users_new (
                    id INTEGER NOT NULL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    password VARCHAR(128) NOT NULL,
                    ss_password TEXT,
                    line_id INTEGER NOT NULL,
                    protocol TEXT DEFAULT 'socks5',
                    listen_port INTEGER,
                    ss_method TEXT,
                    owner_name TEXT,
                    project_name TEXT,
                    speed_limit TEXT,
                    traffic_limit TEXT,
                    status INTEGER,
                    expire_at DATETIME,
                    bytes_in INTEGER,
                    bytes_out INTEGER,
                    note TEXT,
                    created_at DATETIME,
                    FOREIGN KEY(line_id) REFERENCES lines (id)
                )
            """))
            conn.execute(text("""
                INSERT INTO proxy_users_new (
                    id, username, password, ss_password, line_id, protocol, listen_port,
                    ss_method, owner_name, project_name, speed_limit, traffic_limit,
                    status, expire_at, bytes_in, bytes_out, note, created_at
                )
                SELECT
                    id, username, password, ss_password, line_id, protocol, listen_port,
                    ss_method, owner_name, project_name, speed_limit, traffic_limit,
                    status, expire_at, bytes_in, bytes_out, note, created_at
                FROM proxy_users
            """))
            conn.execute(text("DROP TABLE proxy_users"))
            conn.execute(text("ALTER TABLE proxy_users_new RENAME TO proxy_users"))
            print("[migrate] proxy_users global unique username/listen_port removed")

def init_db():
    Base.metadata.create_all(engine)
    _migrate_db()
    s = SessionLocal()
    try:
        if not s.query(AdminUser).filter_by(username="admin").first():
            admin = AdminUser(username="admin", is_super=1)
            admin.set_password("admin123")
            s.add(admin)
            s.commit()
            print("[init_db] default admin created: admin / admin123")
        default_perms = "dashboard,lines,nodes,customers"
        changed = False
        for user in s.query(AdminUser).filter_by(is_super=0).all():
            if not user.permissions:
                user.permissions = default_perms
                changed = True
        if changed:
            s.commit()
    finally:
        s.close()


def get_session():
    return SessionLocal()


if __name__ == "__main__":
    init_db()
    print(f"DB initialized at: {DB_PATH}")
