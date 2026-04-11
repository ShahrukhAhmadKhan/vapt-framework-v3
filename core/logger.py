import datetime

class SocketLogger:
    """Logs to both terminal and WebSocket for live GUI output."""
    def __init__(self, socketio, session_id):
        self.socketio   = socketio
        self.session_id = session_id

    def _emit(self, level, msg):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        try:
            self.socketio.emit("log", {
                "session_id": self.session_id,
                "level": level, "msg": str(msg), "ts": ts,
            })
        except Exception:
            pass
        colours = {
            "info":    "\033[94m", "success": "\033[92m",
            "warning": "\033[93m", "error":   "\033[91m",
            "debug":   "\033[96m", "banner":  "\033[1m\033[96m",
            "finding": "\033[93m",
        }
        c = colours.get(level, "")
        print(f"{c}[{ts}] [{level.upper():<7}] {msg}\033[0m")

    def info(self, msg):    self._emit("info", msg)
    def success(self, msg): self._emit("success", msg)
    def warning(self, msg): self._emit("warning", msg)
    def error(self, msg):   self._emit("error", msg)
    def debug(self, msg):   self._emit("debug", msg)
    def banner(self, msg):  self._emit("banner", f"{'─'*4} {msg} {'─'*4}")
    def finding(self, severity, title, detail=""):
        self._emit("finding", f"[{severity}] {title}" + (f" — {detail}" if detail else ""))
