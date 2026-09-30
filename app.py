from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

DB = "expense.db"
SECRET_KEY = "expense-secret-key"


def connect():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS expenses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT NOT NULL,
        date TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


def create_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_user():
    auth = request.headers.get("Authorization")

    if not auth:
        return None

    token = auth.replace("Bearer ", "")

    try:
        data = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )
        return data["user_id"]

    except jwt.InvalidTokenError:
        return None


@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({"message": "Invalid request"}), 400

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"message": "All fields required"}), 400

    conn = connect()

    existing = conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone()

    if existing:
        conn.close()
        return jsonify({"message": "Email already exists"}), 400


    password_hash = generate_password_hash(password)

    cursor = conn.execute(
        """
        INSERT INTO users(name,email,password)
        VALUES(?,?,?)
        """,
        (name,email,password_hash)
    )

    conn.commit()

    user_id = cursor.lastrowid

    conn.close()

    return jsonify({
        "token": create_token(user_id)
    }),201



@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    conn = connect()

    user = conn.execute(
        "SELECT * FROM users WHERE email=?",
        (email,)
    ).fetchone()

    conn.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"message":"Invalid credentials"}),401


    return jsonify({
        "token": create_token(user["id"])
    })



@app.route("/expenses", methods=["POST"])
def add_expense():

    user_id = get_user()

    if not user_id:
        return jsonify({"message":"Unauthorized"}),401


    data = request.get_json()

    required = ["title","amount","category","date"]

    if not all(field in data for field in required):
        return jsonify({"message":"Missing fields"}),400


    conn = connect()

    cursor = conn.execute(
        """
        INSERT INTO expenses
        (user_id,title,amount,category,date)
        VALUES(?,?,?,?,?)
        """,
        (
            user_id,
            data["title"],
            data["amount"],
            data["category"],
            data["date"]
        )
    )

    conn.commit()

    expense = conn.execute(
        "SELECT * FROM expenses WHERE id=?",
        (cursor.lastrowid,)
    ).fetchone()

    conn.close()

    return jsonify(dict(expense)),201



@app.route("/expenses", methods=["GET"])
def get_expenses():

    user_id = get_user()

    if not user_id:
        return jsonify({"message":"Unauthorized"}),401


    period = request.args.get("period")

    conn = connect()

    query = "SELECT * FROM expenses WHERE user_id=?"
    params = [user_id]


    if period:

        days = {
            "week":7,
            "month":30,
            "3months":90
        }

        if period in days:
            date_limit = (
                datetime.now() -
                timedelta(days=days[period])
            ).strftime("%Y-%m-%d")

            query += " AND date>=?"
            params.append(date_limit)


    rows = conn.execute(
        query,
        params
    ).fetchall()

    conn.close()


    return jsonify(
        [dict(row) for row in rows]
    )



@app.route("/expenses/<int:id>", methods=["PUT"])
def update_expense(id):

    user_id=get_user()

    if not user_id:
        return jsonify({"message":"Unauthorized"}),401


    data=request.get_json()

    conn=connect()

    expense=conn.execute(
        "SELECT * FROM expenses WHERE id=?",
        (id,)
    ).fetchone()


    if not expense:
        conn.close()
        return jsonify({"message":"Not found"}),404


    if expense["user_id"] != user_id:
        conn.close()
        return jsonify({"message":"Forbidden"}),403


    conn.execute(
        """
        UPDATE expenses
        SET title=?, amount=?, category=?, date=?
        WHERE id=?
        """,
        (
            data["title"],
            data["amount"],
            data["category"],
            data["date"],
            id
        )
    )

    conn.commit()

    conn.close()

    return jsonify({"message":"Expense updated"})



@app.route("/expenses/<int:id>", methods=["DELETE"])
def delete_expense(id):

    user_id=get_user()

    if not user_id:
        return jsonify({"message":"Unauthorized"}),401


    conn=connect()

    expense=conn.execute(
        "SELECT * FROM expenses WHERE id=?",
        (id,)
    ).fetchone()


    if not expense:
        conn.close()
        return jsonify({"message":"Not found"}),404


    if expense["user_id"] != user_id:
        conn.close()
        return jsonify({"message":"Forbidden"}),403


    conn.execute(
        "DELETE FROM expenses WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return "",204



if __name__=="__main__":
    init_db()
    app.run(port=5004,debug=True)