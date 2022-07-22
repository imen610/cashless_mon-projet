from twilio.rest import Client

def send_verification(to, otp):
    account_sid = "AC410540eaeec4b5e166a2ae51d99f35cb"
    auth_token = "d45c4527c903512550f1404e9b8a9679"
    client = Client(account_sid, auth_token)

    client.messages.create(
        body=f"Your FirePay Wallet Verification code is {otp}, DO NOT share with Anyone!",
        from_="+18304026050",
        to=to
    )
