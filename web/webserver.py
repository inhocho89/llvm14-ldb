from flask import Flask, render_template, request
import os

APP_DIR = "/path/to/app/dir"
APP_NAME = "app_name"

def create_app():
    app = Flask(__name__)

    with app.app_context():
        os.system("python3 construct_index.py {}".format(APP_DIR))

    print("Staring web dashboard...")

    return app

app = create_app()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/req')
def req():
    req_id = request.args.get('id')
    if req_id == None:
        return render_template('error.html')
    if not os.path.exists("templates/timelines"):
        os.mkdir("templates/timelines")

    REL_PATH = "timelines/req{}.svg".format(req_id)
    cwd = os.getcwd()
    if not os.path.exists("templates/{}".format(REL_PATH)):
        cmd = "cd {} && " \
                "python3 {}/../scripts/draw_req.py {} {} && " \
                "mv req{}.svg {}/templates/timelines/"\
                .format(APP_DIR, cwd, APP_NAME, req_id, req_id, cwd)
        os.system(cmd)
    return render_template(REL_PATH)
