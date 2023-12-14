from json import dumps, loads
from uuid import uuid4

from Crypto.Cipher import AES
from flask import abort, Flask
from flask import current_app
from flask import redirect, render_template, request, url_for
from requests import get

from CTFd.models import UserFieldEntries, UserFields, Users, db, Fields
from CTFd.schemas.fields import FieldSchema
from CTFd.utils import email, get_config, get_app_config, config
from CTFd.utils import user as current_user
from CTFd.utils import validators
from CTFd.utils.config import is_teams_mode
from CTFd.utils.decorators import ratelimit
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.helpers import get_errors
from CTFd.utils.logging import log
from CTFd.utils.validators import ValidationError


def padding(msg: bytes):
    return msg + bytes.fromhex((hex(16 - len(msg) % 16)[2:]).rjust(2, "0")) * (16 - len(msg) % 16)


def unpadding(msg: bytes) -> bytes:
    if len(msg) == 0:
        return b""
    return msg[:len(msg) - int(msg[-1])]


def encrypt(msg: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, key[:16]).encrypt(padding(msg))


def decrypt(msg: bytes, key: bytes) -> bytes:
    return unpadding(AES.new(key, AES.MODE_CBC, key[:16]).decrypt(msg))


def check(code: str, state: str, client_id: str, client_secret: str) -> dict:
    url = f"https://api.hduhelp.com/oauth/token/"
    params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "state": state
    }
    return get(url, params=params).json()


@check_registration_visibility
@ratelimit(method="POST", limit=10, interval=5)
def register():
    errors = get_errors()
    if current_user.authed():
        return redirect(url_for("challenges.listing"))

    num_users_limit = int(get_config("num_users", default=0))
    num_users = Users.query.filter_by(banned=False, hidden=False).count()
    if num_users_limit and num_users >= num_users_limit:
        abort(
            403,
            description=f"Reached the maximum number of users ({num_users_limit}).",
        )

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email_address = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        website = request.form.get("website")
        affiliation = request.form.get("affiliation")
        country = request.form.get("country")
        registration_code = str(request.form.get("registration_code", ""))

        name_len = len(name) == 0
        names = (
            Users.query.add_columns(Users.name, Users.id).filter_by(name=name).first()
        )
        emails = (
            Users.query.add_columns(Users.email, Users.id)
            .filter_by(email=email_address)
            .first()
        )
        pass_short = len(password) == 0
        pass_long = len(password) > 128
        valid_email = validators.validate_email(email_address)
        team_name_email_check = validators.validate_email(name)

        if get_config("registration_code"):
            if (
                    registration_code.lower()
                    != str(get_config("registration_code", default="")).lower()
            ):
                errors.append("The registration code you entered was incorrect")

        # Process additional user fields
        fields = {}
        for field in UserFields.query.all():
            fields[field.id] = field

        entries = {}
        for field_id, field in fields.items():
            value = request.form.get(f"fields[{field_id}]", "").strip()
            if field.required is True and (value is None or value == ""):
                errors.append("Please provide all required fields")
                break

            if field.field_type == "boolean":
                entries[field_id] = bool(value)
            else:
                entries[field_id] = value

        if country:
            try:
                validators.validate_country_code(country)
                valid_country = True
            except ValidationError:
                valid_country = False
        else:
            valid_country = True

        if website:
            valid_website = validators.validate_url(website)
        else:
            valid_website = True

        if affiliation:
            valid_affiliation = len(affiliation) < 128
        else:
            valid_affiliation = True

        client_id = get_app_config("HDU_OA_CLIENT_ID")
        redirect_uri = get_app_config("HDU_OA_REDIRECT_URI")

        if client_id is None:
            errors.append("Please contact website administrator, HDU_OA_CLIENT_ID is None")
        if redirect_uri is None:
            errors.append("Please contact website administrator, HDU_OA_REDIRECT_URI is None")

        if not valid_email:
            errors.append("Please enter a valid email address")
        if email.check_email_is_whitelisted(email_address) is False:
            errors.append("Your email address is not from an allowed domain")
        if names:
            errors.append("That user name is already taken")
        if team_name_email_check is True:
            errors.append("Your user name cannot be an email address")
        if emails:
            errors.append("That email has already been used")
        if pass_short:
            errors.append("Pick a longer password")
        if pass_long:
            errors.append("Pick a shorter password")
        if name_len:
            errors.append("Pick a longer user name")
        if valid_website is False:
            errors.append("Websites must be a proper URL starting with http or https")
        if valid_country is False:
            errors.append("Invalid country")
        if valid_affiliation is False:
            errors.append("Please provide a shorter affiliation")

        if len(errors) > 0:
            return render_template(
                "register.html",
                errors=errors,
                name=request.form["name"],
                email=request.form["email"],
                password=request.form["password"],
            )
        else:
            with current_app.app_context():
                data = {
                    "name": name,
                    "email": email_address,
                    "password": password
                }
                key = str(uuid4())[:32]
                state = encrypt(dumps(data).encode(), key.encode()).hex()
                if get_app_config("AES_KEYS") is None:
                    current_app.config["AES_KEYS"] = {}
                current_app.config["AES_KEYS"][state] = key
                user = Users(name=name, email=email_address, password=password)
                user.banned = True

                if website:
                    user.website = website
                if affiliation:
                    user.affiliation = affiliation
                if country:
                    user.country = country

                db.session.add(user)
                db.session.commit()
                db.session.flush()

                for field_id, value in entries.items():
                    entry = UserFieldEntries(
                        field_id=field_id, value=value, user_id=user.id
                    )
                    db.session.add(entry)
                db.session.commit()
                db.session.close()
                url = f"https://api.hduhelp.com/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&state={state}"
                return redirect(url)
    else:
        return render_template("register.html", errors=errors)


def load(app: Flask):
    app.view_functions["auth.register"] = register

    @app.route("/ctfd/redirect", methods=["GET"])
    @ratelimit(method="GET", limit=10, interval=60)
    def ctfd_redirect():
        client_id = get_app_config("HDU_OA_CLIENT_ID")
        client_secret = get_app_config("HDU_OA_CLIENT_SECRET")
        oauth_code = request.args.get("code")
        state = request.args.get("state")
        keys = get_app_config("AES_KEYS")
        if keys is None or client_id is None or client_secret is None:
            return render_template("register.html", errors=["Invalid code or state"])
        data = loads(decrypt(bytes.fromhex(state), keys[state].encode()))
        username, email_address, password = data["name"], data["email"], data["password"]
        user = Users(name=username, email=email_address, password=password)
        rep = check(oauth_code, state, client_id, client_secret)
        if rep["error"] != 0:
            db.session.delete(user)
            db.session.commit()
            db.session.flush()
            db.session.delete(UserFieldEntries.query.filter_by(user_id=user.id).first())
            db.session.commit()
            db.session.flush()
            db.session.close()
            return render_template("register.html", errors=[rep["msg"]])
        Users.query.filter(Users.name == username, Users.email == email_address).update({"banned": False})
        user = Users.query.filter(Users.name == username, Users.email == email_address).first()
        db.session.commit()
        db.session.flush()
        name = rep["data"]["staff_name"]
        stdId = rep["data"]["staff_id"]
        fields = [i[0] for i in Fields.query.with_entities(Fields.name).distinct().all()]
        for i in ["姓名", "学号"]:
            if i not in fields:
                field = {
                    "id": 0.8763537740868184,
                    "type": "user",
                    "field_type": "text",
                    "name": i,
                    "description": "",
                    "editable": False,
                    "required": False,
                    "public": False
                }
                schema = FieldSchema()
                response = schema.load(field, session=db.session)
                if response.errors:
                    return {"success": False, "errors": response.errors}, 400
                db.session.add(response.data)
                db.session.commit()
                schema.dump(response.data)
                db.session.close()
        name_id = Fields.query.filter_by(name="姓名").first().id
        id_id = Fields.query.filter_by(name="学号").first().id
        db.session.delete(UserFieldEntries.query.filter_by(field_id=name_id, user_id=user.id).first())
        db.session.delete(UserFieldEntries.query.filter_by(field_id=id_id, user_id=user.id).first())
        db.session.add(UserFieldEntries(field_id=name_id, value=name, user_id=user.id))
        db.session.add(UserFieldEntries(field_id=id_id, value=stdId, user_id=user.id))
        db.session.commit()
        db.session.close()
        if config.can_send_mail() and get_config(
                "verify_emails"
        ):  # Confirming users is enabled and we can send email.
            log(
                "registrations",
                format="[{date}] {ip} - {name} registered (UNCONFIRMED) with {email}",
                name=username,
                email=email_address,
            )
            email.verify_email_address(email_address)
            db.session.close()
            return redirect(url_for("auth.confirm"))
        else:  # Don't care about confirming users
            if (
                    config.can_send_mail()
            ):  # We want to notify the user that they have registered.
                email.successful_registration_notification(email_address)
        log(
            "registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=username,
            email=email_address,
        )
        if is_teams_mode():
            return redirect(url_for("teams.private"))
        return redirect(url_for("challenges.listing"))



