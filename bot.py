import discord
import pangea.exceptions as pe
from pangea.config import PangeaConfig
from pangea.services import Redact
from pangea.services import UrlIntel
from pangea.services import DomainIntel
import re
import json

# Set Pangea authentication token and domain
token = "your_pangea_token"
domain = "aws.us.pangea.cloud"
config = PangeaConfig(domain=domain)


def find_domain(text):
    domain_regex = r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}"
    match = re.search(domain_regex, text)
    if match:
        domain = match.group(0)
        return domain
    else:
        return None
        
# Redaction function using Pangea Cloud
def go_redact(text):
    redact = Redact(token, config=config)
    print(f"Redacting PII from: {text}")
    try:
        redact_response = redact.redact(text=text, rulesets=["SECRETS"])
        print(f"Redacted text: {redact_response.result.redacted_text}")
        
        # Check if the original text was redacted
        if text == redact_response.result.redacted_text:
            return ""
        return redact_response.result.redacted_text
    
    except pe.PangeaAPIException as e:
        print(f"Embargo Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
        return False

# URL intelligence function using Pangea Cloud
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


def go_whois(domain):
    intel = DomainIntel(token, config=config)
    print("Checking domain...")

    try:
        response = intel.who_is(domain=domain, provider="whoisxml", verbose=True, raw=True)
        print(f"Response: {response.result.data}")
        domain_name = response.result.data.domain_name
        domain_availability = response.result.data.domain_availability
        created_date = response.result.data.created_date
        registrar_name = response.result.data.registrar_name
        registrant_organization = response.result.data.registrant_organization
        return [domain_name, domain_availability, created_date, registrar_name, registrant_organization]

    except pe.PangeaAPIException as e:
        print(f"Request Error: {e.response.summary}")
        for err in e.errors:
            print(f"\t{err.detail} \n")
            return None

# Discord client class
class MyClient(discord.Client):
    
    async def on_ready(self):
        # Event handler when the bot is ready and connected
        print(f'Logged on as {self.user}!')
    
    async def on_message(self, message):
        # Event handler for incoming messages
        
        # Print the details of the incoming message
        print(f'Message from {message.author}: {message.content}')
        
        # Ignore messages from the bot itself
        if message.author == self.user:
            return
        
        # Redact sensitive information in the message content
        redacted_msg = go_redact(message.content)
        
        # Check if redaction resulted in any changes
        if redacted_msg != "":
            # Delete the original message
            await message.delete()
            # Send a notification about the detected API key
            await message.channel.send("API Key found!")
            # Send the redacted message
            await message.channel.send(redacted_msg)
        
        # Search for URLs in the message content
        match = re.search(r'(http|https)://(?P<hostname>[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*)[^\s]+', message.content)
        
        if match:
            # Extract the detected URL
            detected_url = match.group()
            print(f"Detected URL: {detected_url}")
            # Check the intelligence of the URL
            url_verdict = go_url_intel(detected_url)
            if url_verdict != "":
                # If the URL is deemed malicious, send a warning to the channel
                if url_verdict == "malicious":
                    await message.channel.send("Malicious website found!",  reference=message)

        if message.content.startswith('!whois'):
            input_domain = find_domain(message.content)
            if input_domain is not None:
                whois_response = go_whois(input_domain)
                if whois_response is not None:
                    domain_name, domain_availability, created_date, registrar_name, registrant_organization = whois_response

                    embed = discord.Embed(title="Whois", description="This is an important announcement for all members.", color=discord.Color.blue())
                    embed.add_field(name="Domain Name", value=domain_name)
                    embed.add_field(name="Domain Availability", value=domain_availability)
                    embed.add_field(name="Created Date", value=created_date)
                    embed.add_field(name="Registrar Name", value=registrar_name)
                    embed.add_field(name="Registrant Organization", value=registrant_organization)

                
                await message.reply(embed=embed, mention_author=True)
                


# Set up Discord intents
intents = discord.Intents.default()
intents.message_content = True

# Create an instance of the Discord client
client = MyClient(intents=intents)
# Run the bot with the provided token
client.run('your_bot_token')
