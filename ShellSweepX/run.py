from fastapi import FastAPI, Request, Form, File, UploadFile, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse, Response
import uvicorn
from pydantic import BaseModel
from cryptography.fernet import Fernet
import json
import os
import joblib
import hashlib
import sqlite3
from openai import OpenAI
import math
import requests
from typing import List
from datetime import datetime, timedelta
import yara
from pathlib import Path
import cryptography
import yaml
from anthropic import Anthropic
import base64
import logging
import json
from urllib.parse import quote
import sqlite3
from contextlib import contextmanager
from sqlite3 import Connection
from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect
import re

DB_POOL = sqlite3.connect("shell_sweep_ml.db", check_same_thread=False)


@contextmanager
def get_db_connection():
    conn = DB_POOL
    try:
        yield conn
    finally:
        conn.commit()


def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.executescript(
            """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            sha256 TEXT NOT NULL,
            file_name TEXT NOT NULL,
            result TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            content TEXT NOT NULL,
            feedback INTEGER DEFAULT 0,
            analysis TEXT,
            entropy REAL,
            std_dev REAL,
            vt_score TEXT,
            yara_matches TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            submitted_timestamp TEXT,
            last_analyzed_timestamp TEXT,
            submitting_agents TEXT
        );
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT UNIQUE,
            computer_name TEXT,
            last_checkin TEXT
        );
        """
        )


app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY_FILE = "secret.key"

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, "rb") as key_file:
        SECRET_KEY = key_file.read()
else:
    SECRET_KEY = Fernet.generate_key()
    with open(SECRET_KEY_FILE, "wb") as key_file:
        key_file.write(SECRET_KEY)

cipher_suite = Fernet(SECRET_KEY)

YARA_RULES_DIR = Path("yara_rules")
YARA_RULES_DIR.mkdir(exist_ok=True)


class Settings(BaseModel):
    vt_api_key: str = ""
    gpt_api_key: str = ""
    claude_api_key: str = ""
    yara_enabled: bool = False
    yara_rules: dict = {}
    ai_prompt: str = (
        "You are an AI assistant tasked with analyzing potential webshells. Please analyze the following code and provide insights on whether it might be a webshell, its capabilities, and any suspicious elements."
    )


def load_settings():
    try:
        with open("settings.json", "rb") as f:
            encrypted_data = f.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            settings_dict = json.loads(decrypted_data)
            settings = Settings(**settings_dict)
            settings.yara_rules = load_yara_rules()
            return settings
    except (FileNotFoundError, json.JSONDecodeError, cryptography.fernet.InvalidToken):
        return Settings()


def save_settings(settings: Settings):
    settings_dict = settings.dict()
    settings_dict.pop("yara_rules", None)
    encrypted_data = cipher_suite.encrypt(json.dumps(settings_dict).encode())
    with open("settings.json", "wb") as f:
        f.write(encrypted_data)
    for filename, content in settings.yara_rules.items():
        save_yara_rule(filename, content)


def save_yara_rule(filename, content):
    rule_path = YARA_RULES_DIR / filename
    rule_path.write_text(content)


@app.get("/")
async def read_root(request: Request):
    with get_db_connection() as conn:
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM findings")
        files_scanned = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM findings WHERE result = 'Webshell detected'")
        webshells_detected = c.fetchone()[0]

        detection_rate = (
            (webshells_detected / files_scanned * 100) if files_scanned > 0 else 0
        )

        c.execute(
            """
            SELECT file_name, datetime(created_at, 'localtime') as detected_time 
            FROM findings 
            WHERE result = 'Webshell detected' 
            ORDER BY created_at DESC LIMIT 5
        """
        )
        recent_detections = [
            {"file_name": row[0], "detected_time": row[1]} for row in c.fetchall()
        ]

        c.execute(
            """
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
            FROM findings
            WHERE result = 'Webshell detected'
            AND created_at >= date('now', '-6 months')
            GROUP BY month
            ORDER BY month
        """
        )
        formatted_trend_data = [
            {"month": row[0], "count": row[1]} for row in c.fetchall()
        ]

    recent_agent_count = get_active_agent_count()

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "webshells_detected": webshells_detected,
            "files_scanned": files_scanned,
            "detection_rate": f"{detection_rate:.2f}",
            "recent_agent_count": recent_agent_count,
            "recent_detections": recent_detections,
            "trend_data": formatted_trend_data,
        },
    )


@app.get("/agents")
async def agents_page(request: Request):
    settings = load_settings()
    return templates.TemplateResponse(
        "agents.html", {"request": request, "settings": settings}
    )


@app.get("/settings")
async def settings_page(request: Request):
    settings = load_settings()
    yara_rules = load_yara_rules()
    message = request.query_params.get("message")
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "settings": settings,
            "yara_rules": yara_rules,
            "message": message,
        },
    )


@app.post("/save_settings")
async def save_settings_route(request: Request):
    try:
        form_data = await request.form()
        settings = load_settings()
        settings.gpt_api_key = form_data.get("gpt_api_key", "")
        settings.claude_api_key = form_data.get("claude_api_key", "")
        settings.ai_prompt = form_data.get("ai_prompt", "")
        settings.yara_enabled = form_data.get("yara_enabled") == "on"
        save_settings(settings)

        logging.info("Settings saved successfully")
        return RedirectResponse(
            url="/settings?message=Settings saved successfully", status_code=303
        )
    except Exception as e:
        logging.error(f"Error saving settings: {str(e)}")
        return RedirectResponse(
            url="/settings?message=Error saving settings: {str(e)}", status_code=303
        )


# Load the model and vectorizer
clf = joblib.load("models/model.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")


def insert_into_db(
    sha256,
    file_name,
    result,
    file_size,
    content,
    entropy,
    std_dev,
    yara_matches,
    submitting_agent,
):
    with get_db_connection() as conn:
        c = conn.cursor()
        current_time = datetime.now().isoformat()
        c.execute(
            """INSERT OR REPLACE INTO findings 
                     (sha256, file_name, result, file_size, content, entropy, std_dev, yara_matches, created_at, submitted_timestamp, last_analyzed_timestamp, submitting_agents) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sha256,
                file_name,
                result,
                file_size,
                content,
                entropy,
                std_dev,
                yara_matches,
                current_time,
                current_time,
                current_time,
                submitting_agent,
            ),
        )


def get_findings_from_db(limit=None, offset=0):
    with get_db_connection() as conn:
        c = conn.cursor()
        if limit:
            c.execute(
                "SELECT sha256, file_name, result, file_size, analysis, entropy, std_dev FROM findings ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        else:
            c.execute(
                "SELECT sha256, file_name, result, file_size, analysis, entropy, std_dev FROM findings ORDER BY id DESC"
            )
        findings = c.fetchall()
    return findings


def search_findings(query, limit=10, offset=0):
    with get_db_connection() as conn:
        c = conn.cursor()
        if query:
            search_query = " OR ".join(
                [
                    "sha256 LIKE ?",
                    "file_name LIKE ?",
                    "result LIKE ?",
                    "analysis LIKE ?",
                    "yara_matches LIKE ?",
                    "submitting_agents LIKE ?",
                ]
            )
            params = [f"%{query}%"] * 6 + [limit, offset]

            c.execute(
                f"""
                SELECT sha256, file_name, result, file_size, content, analysis, entropy, std_dev, yara_matches, submitted_timestamp, last_analyzed_timestamp, submitting_agents 
                FROM findings 
                WHERE {search_query}
                ORDER BY id DESC LIMIT ? OFFSET ?
            """,
                params,
            )
        else:
            c.execute(
                """
                SELECT sha256, file_name, result, file_size, content, analysis, entropy, std_dev, yara_matches, submitted_timestamp, last_analyzed_timestamp, submitting_agents 
                FROM findings 
                ORDER BY id DESC LIMIT ? OFFSET ?
            """,
                (limit, offset),
            )
        findings = c.fetchall()
    return [
        {
            "sha256": f[0],
            "file_name": f[1],
            "result": f[2],
            "file_size": f[3],
            "content": f[4],
            "analysis": f[5],
            "entropy": f[6],
            "std_dev": f[7],
            "yara_matches": f[8],
            "submitted_timestamp": f[9],
            "last_analyzed_timestamp": f[10],
            "submitting_agents": f[11],
        }
        for f in findings
    ]


def count_search_results(query):
    with get_db_connection() as conn:
        c = conn.cursor()
        if query:
            search_query = " OR ".join(
                [
                    "sha256 LIKE ?",
                    "file_name LIKE ?",
                    "result LIKE ?",
                    "analysis LIKE ?",
                    "yara_matches LIKE ?",
                    "submitting_agents LIKE ?",
                ]
            )
            params = [f"%{query}%"] * 6
            c.execute(f"SELECT COUNT(*) FROM findings WHERE {search_query}", params)
        else:
            c.execute("SELECT COUNT(*) FROM findings")
        count = c.fetchone()[0]
    return count


# Analysis functions
def predict_file_content(file_content):
    sha256_hash = hashlib.sha256(file_content.encode()).hexdigest()
    X_new = vectorizer.transform([file_content])
    prediction = clf.predict(X_new)
    if prediction[0] == 1:
        return sha256_hash, "Webshell detected"
    else:
        return sha256_hash, "File seems benign"


def calculate_entropy(content):
    if not content:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(content.count(chr(x))) / len(content)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


def calculate_std_dev(values):
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def yara_scan(file_content, rules):
    matches = []
    errors = []
    for rule_name, rule_info in rules.items():
        if rule_info["is_valid"]:
            try:
                compiled_rule = yara.compile(source=rule_info["content"])
                rule_matches = compiled_rule.match(data=file_content)
                if rule_matches:
                    matches.extend([match.rule for match in rule_matches])
            except yara.Error as e:
                errors.append(f"Error in rule '{rule_name}': {str(e)}")

    if errors:
        return [f"YARA compilation errors: {'; '.join(errors)}"]
    return matches


@app.post("/upload")
async def upload_files(files: List[UploadFile] = File(...)):
    results = []
    for file in files:
        content = await file.read()
        content_str = content.decode("utf-8", errors="ignore")
        sha256, result = predict_file_content(content_str)
        file_size = len(content)
        entropy = calculate_entropy(content_str)
        std_dev = calculate_std_dev([ord(c) for c in content_str])
        settings = load_settings()
        yara_matches = []
        if settings.yara_enabled and settings.yara_rules:
            yara_matches = yara_scan(content_str, settings.yara_rules)
        insert_into_db(
            sha256,
            file.filename,
            result,
            file_size,
            content_str,
            entropy,
            std_dev,
            ",".join(yara_matches),
            "Manual Upload",
        )
        results.append({"filename": file.filename, "result": result, "sha256": sha256})
    return {"results": results}


@app.get("/analysis")
async def analysis_page(request: Request):
    return templates.TemplateResponse("analysis.html", {"request": request})


@app.get("/search")
async def search(
    query: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
):
    offset = (page - 1) * page_size
    results = search_findings(query, limit=page_size, offset=offset)
    total_results = count_search_results(query)
    total_pages = math.ceil(total_results / page_size)
    return JSONResponse(
        {
            "results": results,
            "page": page,
            "total_pages": total_pages,
            "total_results": total_results,
        }
    )


def update_agent_checkin(agent_id, computer_name):
    with get_db_connection() as conn:
        c = conn.cursor()
        current_time = datetime.now().isoformat()
        c.execute(
            """
            INSERT INTO agents (agent_id, computer_name, last_checkin)
            VALUES (?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
            computer_name = excluded.computer_name,
            last_checkin = excluded.last_checkin
        """,
            (agent_id, computer_name, current_time),
        )


def get_agents():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT agent_id, computer_name, last_checkin FROM agents ORDER BY last_checkin DESC"
        )
        agents = [
            {"agent_id": row[0], "computer_name": row[1], "last_checkin": row[2]}
            for row in c.fetchall()
        ]
    return agents


def get_active_agent_count():
    with get_db_connection() as conn:
        c = conn.cursor()
        twenty_four_hours_ago = datetime.now() - timedelta(hours=24)
        c.execute(
            "SELECT COUNT(DISTINCT computer_name) FROM agents WHERE last_checkin > ?",
            (twenty_four_hours_ago.isoformat(),),
        )
        count = c.fetchone()[0]
    return count


@app.post("/api/agent_checkin")
async def agent_checkin(agent_data: dict):
    try:
        agent_id = agent_data["agent_id"]
        computer_name = agent_data["computer_name"]
        update_agent_checkin(agent_id, computer_name)
        return JSONResponse({"message": "Agent check-in recorded successfully"})
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing required field: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/agents")
async def get_agent_list():
    return get_agents()


init_db()


def load_yara_rules():
    rules = {}
    for rule_file in YARA_RULES_DIR.glob("*.yar"):
        content = rule_file.read_text()
        try:
            yara.compile(source=content)
            is_valid = True
        except yara.Error:
            is_valid = False
        rules[rule_file.name] = {"content": content, "is_valid": is_valid}
    return rules


def yara_scan(file_content, rules):
    matches = []
    errors = []
    for rule_name, rule_info in rules.items():
        if rule_info["is_valid"]:
            try:
                compiled_rule = yara.compile(source=rule_info["content"])
                rule_matches = compiled_rule.match(data=file_content)
                if rule_matches:
                    matches.extend([match.rule for match in rule_matches])
            except yara.Error as e:
                errors.append(f"Error in rule '{rule_name}': {str(e)}")

    if errors:
        return [f"YARA compilation errors: {'; '.join(errors)}"]
    return matches


@app.get("/api/agent_config")
async def get_agent_config():
    try:
        with open("agent_config.yaml", "r") as f:
            config = yaml.safe_load(f)
        return JSONResponse(config)
    except FileNotFoundError:
        return JSONResponse({"error": "Configuration file not found"}, status_code=404)


@app.post("/api/agent_config")
async def save_agent_config(request: Request):
    try:
        config = await request.json()
        with open("agent_config.yaml", "r") as f:
            existing_config = yaml.safe_load(f)

        # Update existing_config with new values
        existing_config["directory_paths"] = config["directory_paths"]
        existing_config["exclude_paths"] = config["exclude_paths"]
        existing_config["file_extensions"] = config["file_extensions"]
        existing_config["ignore_hashes"] = config["ignore_hashes"]

        with open("agent_config.yaml", "w") as f:
            yaml.dump(existing_config, f, default_flow_style=False)

        logging.info("Agent configuration saved successfully")
        return JSONResponse({"message": "Configuration saved successfully"})
    except Exception as e:
        logging.error(f"Error saving agent configuration: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/agent_results")
async def receive_agent_results(request: Request):
    try:
        data = await request.json()
        agent_id = data["agent_id"]
        computer_name = data["computer_name"]
        results = data["results"]

        for result in results:
            file_path = result["FilePath"]
            sha256 = result["Hash"]
            file_size = result["FileSize"]
            last_modified = result["LastModified"]
            file_content = base64.b64decode(result["Content"]).decode(
                "utf-8", errors="ignore"
            )
            sha256, prediction_result = predict_file_content(file_content)
            entropy = calculate_entropy(file_content)
            std_dev = calculate_std_dev([ord(c) for c in file_content])
            settings = load_settings()
            yara_matches = []
            if settings.yara_enabled and settings.yara_rules:
                yara_matches = yara_scan(file_content, settings.yara_rules)
            insert_into_db(
                sha256,
                file_path,
                prediction_result,
                file_size,
                file_content,
                entropy,
                std_dev,
                ",".join(yara_matches),
                computer_name,
            )

        update_agent_checkin(agent_id, computer_name)
        return JSONResponse({"message": "Results received and processed successfully"})
    except Exception as e:
        logging.error(f"Error processing agent results: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/scan_database_with_yara")
async def scan_database_with_yara():
    settings = load_settings()
    if not settings.yara_enabled:
        return JSONResponse({"message": "YARA scanning is not enabled in settings."})

    yara_rules = load_yara_rules()
    valid_rules = {
        name: rule_info
        for name, rule_info in yara_rules.items()
        if rule_info["is_valid"]
    }

    if not valid_rules:
        return JSONResponse({"message": "No valid YARA rules are defined."})

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "SELECT id, content FROM findings WHERE yara_matches IS NULL OR yara_matches = ''"
        )
        findings = c.fetchall()

        updated_count = 0
        errors = []
        for finding_id, content in findings:
            try:
                yara_matches = yara_scan(content, valid_rules)
                if yara_matches:
                    c.execute(
                        "UPDATE findings SET yara_matches = ? WHERE id = ?",
                        (",".join(yara_matches), finding_id),
                    )
                    updated_count += 1
            except Exception as e:
                errors.append(f"Error processing finding {finding_id}: {str(e)}")

    log_message = (
        f"YARA scan complete. Updated {updated_count} findings with YARA matches."
    )
    if errors:
        log_message += f" Errors encountered: {'; '.join(errors)}"
    logging.info(log_message)
    return JSONResponse({"message": log_message})


@app.post("/triage_with_ai")
async def triage_with_ai(sha256: str = Form(...)):
    settings = load_settings()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT content FROM findings WHERE sha256 = ?", (sha256,))
        content = c.fetchone()

    if not content:
        return JSONResponse({"error": "File not found"}, status_code=404)

    content = content[0]
    chunks = chunk_content(content)

    if settings.gpt_api_key:
        analysis = analyze_with_gpt(chunks, settings.gpt_api_key, settings.ai_prompt)
    elif settings.claude_api_key:
        analysis = analyze_with_claude(
            chunks, settings.claude_api_key, settings.ai_prompt
        )
    else:
        return JSONResponse({"error": "No AI API key configured"}, status_code=400)

    current_time = datetime.now().isoformat()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE findings SET analysis = ?, last_analyzed_timestamp = ? WHERE sha256 = ?",
            (analysis, current_time, sha256),
        )

    return JSONResponse({"analysis": analysis})


def chunk_content(content, chunk_size=4000):
    return [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)]


def analyze_with_gpt(chunks, api_key, prompt):
    client = OpenAI(api_key=api_key)
    full_analysis = ""
    for chunk in chunks:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": chunk},
            ],
        )
        full_analysis += response.choices[0].message.content + "\n\n"
    return full_analysis.strip()


def analyze_with_claude(chunks, api_key, prompt):
    client = Anthropic(api_key=api_key)
    full_analysis = ""
    for chunk in chunks:
        response = client.messages.create(
            model="claude-3-5-sonnet-20240620",
            max_tokens=1000,
            messages=[
                {
                    "role": "user",
                    "content": f"{prompt}\n\nHere's the code chunk:\n{chunk}",
                }
            ],
        )
        full_analysis += response.content[0].text + "\n\n"
    return full_analysis.strip()


def log_event(event_type, data):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "data": data,
    }
    logging.info(json.dumps(log_entry))


logging.basicConfig(
    level=logging.INFO, format="%(message)s", filename="shellsweepx.log", filemode="a"
)


@app.post("/add_yara_rule")
async def add_yara_rule(request: Request):
    try:
        data = await request.json()
        filename = data["filename"]
        content = data["content"]

        if not filename.endswith(".yar"):
            filename += ".yar"

        file_path = YARA_RULES_DIR / filename

        if file_path.exists():
            return JSONResponse(
                {"message": "A rule with this name already exists."}, status_code=400
            )

        try:
            yara.compile(source=content)
        except yara.Error as e:
            return JSONResponse(
                {"message": f"Invalid YARA rule: {str(e)}"}, status_code=400
            )

        file_path.write_text(content)
        return JSONResponse({"message": "YARA rule added successfully."})
    except Exception as e:
        logging.error(f"Error adding YARA rule: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/update_yara_rule")
async def update_yara_rule(request: Request):
    try:
        data = await request.json()
        filename = data["filename"]
        content = data["content"]

        file_path = YARA_RULES_DIR / filename

        if not file_path.exists():
            return JSONResponse({"message": "Rule not found."}, status_code=404)

        try:
            yara.compile(source=content)
        except yara.Error as e:
            return JSONResponse(
                {"message": f"Invalid YARA rule: {str(e)}"}, status_code=400
            )

        file_path.write_text(content)
        return JSONResponse({"message": "YARA rule updated successfully."})
    except Exception as e:
        logging.error(f"Error updating YARA rule: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/delete_yara_rule")
async def delete_yara_rule(request: Request):
    try:
        data = await request.json()
        filename = data["filename"]

        file_path = YARA_RULES_DIR / filename

        if not file_path.exists():
            return JSONResponse({"message": "Rule not found."}, status_code=404)

        file_path.unlink()
        return JSONResponse({"message": "YARA rule deleted successfully."})
    except Exception as e:
        logging.error(f"Error deleting YARA rule: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/recent_detections")
async def get_recent_detections():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(
            """
            SELECT file_name, datetime(created_at, 'localtime') as detected_time, result
            FROM findings 
            WHERE result = 'Webshell detected' 
            ORDER BY created_at DESC LIMIT 5
        """
        )
        recent_detections = [
            {
                "file_name": row[0],
                "detected_time": row[1],
                "severity": get_severity(row[2]),
            }
            for row in c.fetchall()
        ]
    return JSONResponse(recent_detections)


def get_severity(result):
    if "high" in result.lower():
        return "high"
    elif "medium" in result.lower():
        return "medium"
    elif "low" in result.lower():
        return "low"
    else:
        return "unknown"


connected_clients = set()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


async def broadcast_message(message: dict):
    for client in connected_clients:
        await client.send_json(message)


@app.get("/api/chart_data")
async def get_chart_data():
    try:
        with get_db_connection() as conn:
            c = conn.cursor()

            c.execute(
                """
                SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
                FROM findings
                WHERE result = 'Webshell detected'
                AND created_at >= date('now', '-6 months')
                GROUP BY month
                ORDER BY month
            """
            )
            trend_data = c.fetchall()

            c.execute(
                """
                WITH extension_counts AS (
                    SELECT 
                        CASE 
                            WHEN instr(file_name, '.') > 0 
                            THEN upper(substr(file_name, instr(file_name, '.') + 1))
                            ELSE 'Unknown'
                        END as extension,
                        COUNT(*) as count
                    FROM findings
                    WHERE result = 'Webshell detected'
                    GROUP BY extension
                )
                SELECT 
                    CASE 
                        WHEN count > (SELECT 0.05 * SUM(count) FROM extension_counts)
                        THEN extension
                        ELSE 'Other'
                    END as type,
                    SUM(count) as count
                FROM extension_counts
                GROUP BY 
                    CASE 
                        WHEN count > (SELECT 0.05 * SUM(count) FROM extension_counts)
                        THEN extension
                        ELSE 'Other'
                    END
                ORDER BY count DESC
            """
            )
            types_data = c.fetchall()

        result = {
            "trend": {
                "labels": [row[0] for row in trend_data],
                "data": [row[1] for row in trend_data],
            },
            "types": {
                "labels": [row[0] for row in types_data],
                "data": [row[1] for row in types_data],
            },
        }
        print("Chart data:", result)
        return JSONResponse(result)
    except Exception as e:
        print(f"Error in get_chart_data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
