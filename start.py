import traceback
import uvicorn

try:
    import web_server
except Exception:
    print("[startup] Failed to import web_server:")
    traceback.print_exc()
    raise

if __name__ == "__main__":
    print("[startup] web_server imported successfully, starting uvicorn...")
    uvicorn.run(web_server.app, host="0.0.0.0", port=8000)
