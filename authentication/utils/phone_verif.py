from twilio.rest import Client

def send_verification(to, otp):
    account_sid = "AC46140924c874212be7cfd338fe52bf16"
    auth_token = "aa2a1f80f390814db13cab3f3b97937c"
    client = Client(account_sid, auth_token)

    client.messages.create(
        body=f"Your FirePay Wallet Verification code is {otp}, DO NOT share with Anyone!",
        from_='+13254201502',
        to=to
    )
