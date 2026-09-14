import threading
import webbrowser

import uvicorn

if __name__ == "__main__":
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:8000")).start()
    print("[+] OSSINT Web running at http://127.0.0.1:8000  (Ctrl+C to stop)")
    uvicorn.run("webapp.server:app", host="127.0.0.1", port=8000, log_level="info")
