from flask import Flask, redirect, render_template, request, session, url_for, make_response, abort
from crypto import *
from enteties.login import Login

app = Flask(__name__)
app.secret_key = "very secret key12312312313212312"


@app.route('/')
def index():
    return redirect('/login')


@app.route('/login', methods=['GET'])
def login_get():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    masterPassword = request.form['masterPassword']
    if not verify_master_password(masterPassword):
        return render_template("login.html", loginError="Invalid password")
    session["masterPassword"] = masterPassword
    return redirect("/vault")


@app.route('/login', methods=['PUT'])
def login_put():
    newPassword = request.form['newPassword']
    if not newPassword:
        return render_template("resetLogin.html", newLoginError="Cannot be empty")
    create_database()
    set_master_password(newPassword)
    session["masterPassword"] = newPassword
    res = make_response("", 200)
    res.headers['HX-Redirect'] = "/vault"
    return res


@app.route('/vault', methods=['GET'])
def vault():
    if 'masterPassword' not in session:
        return redirect("/login")
    id = request.args.get('id', default=None, type=int)
    masterPassword = session.get("masterPassword")
    websites = get_decrypted_websites(masterPassword)
    if id:
        encryptedLogin = get_encrypted_login(id)
        if isinstance(encryptedLogin, EncryptedLogin):
            login = decrypt_login(encryptedLogin, masterPassword)
            return render_template("vault.html", websites=websites, error=None, newLogin=None, login=login)

    return render_template('vault.html', websites=websites, error=None, newLogin=None, login=None)


@app.route('/vault', methods=['POST'])
def vault_post():
    masterPassword = session.get("masterPassword")
    if not masterPassword:
        return redirect("/login")
    newLogin = Login(None, request.form['website'], request.form['email'], request.form['password'])

    if not newLogin.password or not newLogin.email or not newLogin.website:
        error = {}
        if not newLogin.password:
            error["missingPassword"] = "missing password"
        if not newLogin.email:
            error["missingEmail"] = "missing email"
        if not newLogin.website:
            error["missingWebsite"] = "missing website"
        res = make_response(render_template("newLogin.html", error=error, newLogin=newLogin))
        res.headers['HX-Retarget'] = "#contentPane"
        return res

    newId = encrypt_save_login_detail(newLogin, masterPassword)
    return redirect("/vault?id={}".format(newId))


@app.route('/vault', methods=['DELETE'])
def vault_delete():
    if 'masterPassword' not in session:
        return redirect("/login")
    id = request.args.get('id', default=None, type=int)
    masterPassword = session.get("masterPassword")
    delete_login(id)
    websites = get_decrypted_websites(masterPassword)

    return render_template('vault.html', websites=websites, error=None, newLogin=None, login=None)


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect("/login")


if __name__ == '__main__':
    app.run()
