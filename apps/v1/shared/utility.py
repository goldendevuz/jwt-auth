import re
import threading
import phonenumbers
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from icecream import ic
from rest_framework.exceptions import ValidationError
from decouple import config
from twilio.rest import Client

email_regex = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
phone_regex = re.compile(r"(\+[0-9]+\s*)?(\([0-9]+\))?[\s0-9\-]+[0-9]+")
username_regex = re.compile(r"^[a-zA-Z0-9_.-]+$")


# Define the phone number regex
# phone_regex = RegexValidator(
#     regex=r'^\+998\d{9}$',
#     message="Telefon raqam quyidagi formatda bo'lishi kerak: '+998XXXXXXXXX' (masalan, +998901234567)."
# )
    # phone_number = phonenumbers.parse(username_phone_email)
    # if phonenumbers.is_valid_number(phone_number):
    #     username_phone_email = 'phone'

def check_username_phone_email(username_phone_email):
    # ic(username_phone_email)
    if re.fullmatch(email_regex, username_phone_email):
        return "email"
    if re.fullmatch(phone_regex, username_phone_email):
        return "phone"
    data = {
        "message": "Email yoki telefon raqamingiz notogri"
    }
    raise ValidationError(data)

def check_user_type(user_input):
    # phone_number = phonenumbers.parse(user_input)
    if re.fullmatch(email_regex, user_input):
        user_input = 'email'
    elif re.fullmatch(phone_regex, user_input):
        user_input = 'phone'
    elif re.fullmatch(username_regex, user_input):
        user_input = 'username'
    else:
        data = {
            "message": "Email, username yoki telefon raqamingiz noto'g'ri"
        }
        raise ValidationError(data)
    return user_input


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )
        if data.get('content_type') == "html":
            email.content_subtype = 'html'
        EmailThread(email).start()


def send_email(email, code):
    html_content = render_to_string(
        'email/authentication/activate_account.html',
        {"code": code}
    )
    Email.send_email(
        {
            "subject": "Royhatdan otish",
            "to_email": email,
            "body": html_content,
            "content_type": "html"
        }
    )

def send_phone_code(phone, code):
    import requests
    import json

    url = "http://0.0.0.0:2020/api/sms/"

    payload = json.dumps({
    "number": phone.replace("+998", ""),
    "text": f"Salom do'stim! Sizning tasdiqlash kodingiz: {code}\n"
    })
    headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Basic {config("BASIC_AUTH_TOKEN")}',
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    return response.json()




