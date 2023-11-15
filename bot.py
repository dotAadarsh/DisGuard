import discord
import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact
from pangea.services import UrlIntel
import re
import json

token = "your_pangea_token"
domain = "aws.us.pangea.cloud"
config = PangeaConfig(domain=domain)


def go_redact(text):
    redact = Redact(token, config=config)
    print(f"Redacting PII from: {text}")
    try:
        redact_response = redact.redact(text=text, rulesets=["SECRETS"])
        print(f"Redacted text: {redact_response.result.redacted_text}")
        if text == redact_response.result.redacted_text:
            return ""
        return redact_response.result.redacted_text
    
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return False


def go_url_intel(url):
    intel = UrlIntel(token, config=config)
    
    try:
        response = intel.reputation(
            url=url,
            provider="crowdstrike",
            verbose=True,
            raw=True,
        )

        print(f"Response: {response.result}")
        return response.result.data.verdict

    except pe.PangeaAPIException as e:

        print(f"Request Error: {e.response.summary}")

        for err in e.errors:
            print(f"\t{err.detail} \n")
            return err.detail


class MyClient(discord.Client):
    
    async def on_ready(self):
        print(f'Logged on as {self.user}!')
    
    async def on_message(self, message):
        print(f'Message from {message.author}: {message.content}')
        
        if message.author == self.user:
            return
        
        redacted_msg = go_redact(message.content)
        if redacted_msg != "":
            await message.delete()
            await message.channel.send("API Key found!")
            await message.channel.send(redacted_msg)
        
        match = re.search(r'(http|https)://(?P<hostname>[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*)[^\s]+', message.content)
        
        if match:
            detected_url = match.group()
            print(f"Detected URL: {detected_url}")
            url_verdict = go_url_intel(detected_url)
            if url_verdict != "":
                if url_verdict == "malicious":
                    await message.channel.send("Malicious website found!",  reference=message)


intents = discord.Intents.default()
intents.message_content = True
 
client = MyClient(intents=intents)
client.run('your_discord_bot_token')

