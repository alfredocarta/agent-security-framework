import secrets
from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from registry import SessionLocal, AuditModel
import uvicorn

app = FastAPI(title="Agent Security Dashboard")
security = HTTPBasic()

DASHBOARD_USER = "admin"
DASHBOARD_PASSWORD = "asf-secret-2024"
PAGE_SIZE = 20

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, DASHBOARD_USER)
    correct_password = secrets.compare_digest(credentials.password, DASHBOARD_PASSWORD)
    if not (correct_user and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

@app.get("/audit", response_class=HTMLResponse)
def get_dashboard(
    username: str = Depends(verify_credentials),
    page: int = Query(default=1, ge=1)
):
    db = SessionLocal()
    total = db.query(AuditModel).count()
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, total_pages)
    offset = (page - 1) * PAGE_SIZE

    logs = (
        db.query(AuditModel)
        .order_by(AuditModel.timestamp.desc())
        .offset(offset)
        .limit(PAGE_SIZE)
        .all()
    )
    db.close()

    rows = ""
    for log in logs:
        if log.outcome == "KILL_SWITCH":
            color = "red"
        elif log.outcome == "BLOCKED":
            color = "orange"
        else:
            color = "green"

        rows += f"""
        <tr style="border-bottom: 1px solid #ddd;">
            <td style="padding:10px;">{log.timestamp}</td>
            <td style="padding:10px;"><b>{log.agent_id}</b></td>
            <td style="padding:10px; color:{color}; font-weight:bold;">{log.outcome}</td>
            <td style="padding:10px;">{log.reason}</td>
            <td style="padding:10px; font-family:monospace; font-size:10px;">{log.hash[:16]}...</td>
        </tr>
        """

    prev_disabled = "disabled" if page <= 1 else ""
    next_disabled = "disabled" if page >= total_pages else ""

    pagination = f"""
    <div style="margin-top:20px; display:flex; align-items:center; gap:12px;">
        <a href="/audit?page={page - 1}"
           style="padding:8px 16px; background:#333; color:white; text-decoration:none; border-radius:4px; pointer-events: {"none" if page <= 1 else "auto"}; opacity: {"0.4" if page <= 1 else "1"};">
            Previous
        </a>
        <span>Page {page} of {total_pages} ({total} total events)</span>
        <a href="/audit?page={page + 1}"
           style="padding:8px 16px; background:#333; color:white; text-decoration:none; border-radius:4px; pointer-events: {"none" if page >= total_pages else "auto"}; opacity: {"0.4" if page >= total_pages else "1"};">
            Next
        </a>
    </div>
    """

    return f"""
    <html>
        <head><title>Security Audit Dashboard</title></head>
        <body style="font-family: sans-serif; padding: 40px; background: #f4f4f9;">
            <h2>Agent Security Framework - Audit Trail</h2>
            <p>Logged in as: <b>{username}</b></p>
            <table style="width:100%; background:white; border-collapse: collapse; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                <tr style="background:#333; color:white; text-align:left;">
                    <th style="padding:10px;">Timestamp</th>
                    <th style="padding:10px;">Agent ID</th>
                    <th style="padding:10px;">Outcome</th>
                    <th style="padding:10px;">Reason</th>
                    <th style="padding:10px;">Hash Chain</th>
                </tr>
                {rows}
            </table>
            {pagination}
        </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
