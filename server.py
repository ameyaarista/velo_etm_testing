from flask import Flask, Response, send_from_directory
from flask_cors import CORS
import subprocess, os, re

app = Flask(__name__)
CORS(app)

BASE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = {
    0: 'app_filtering.py',
    1: 'domain_rule_test.py',
    2: 'geo_ip_testing.py',
    3: 'idps_testing.py',
}

def strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

@app.route('/run/<int:idx>')
def run_script(idx):
    script = SCRIPTS.get(idx)
    if not script:
        return 'Unknown script', 404
    def generate():
        proc = subprocess.Popen(
            ['python3', '-u', os.path.join(BASE, script), '--no-verify'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            yield f"data: {strip_ansi(line.rstrip())}\n\n"
        yield "data: __DONE__\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/')
@app.route('/<path:filename>')
def serve(filename='etmdemo.html'):
    return send_from_directory(BASE, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
