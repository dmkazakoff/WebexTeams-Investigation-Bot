###### **Cisco CTR API Investigation Bot for Webex Teams**

This is a demonstration of a Proof of Concept webex Chat Bot, leveraging Cisco Threat Response API to do investigations, correlation and enrichment of submitted IoCs.

To run this script, you need a [Webex Developer account](https://developer.webex.com/login), and to follow this documentation to [create a Bot](https://developer.webex.com/docs/bots). [Example of Bot Creation](https://developer.webex.com/blog/spark-bot-demo)
This script will use a Webex Teams Room to log every message sent to and from your Bot. So you will also need to create a room in Webex Teams and include your new Bot in it. Use this [API call](https://developer.webex.com/docs/api/v1/rooms/list-rooms) to find the roomId.

Script itself will create webhook with needed parameters, which you'll include in configuration part at the beginning.

**What you'll to configure variables at the head of the script:**

1. BOT Email address (received on bot creation).
2. BOT name (received on bot creation).
3. BOT Access token (received on bot creation).
4. WEBHook url, where the webhooks are sent from your bot, possible options:  
        - Host your script with direct internet-access/port-forwarding to a port tcp/3000 (default) which script listens.
        - Use [Ngrok](https://ngrok.com/) to be able to run it on you laptop with no worries for firewalls, certificates etc. (Good choiсe for fast start)
4. RoomID (Use [this](https://developer.webex.com/docs/api/v1/rooms/list-rooms) API call to find it), which you've created and invited your freshly created bot into it.
5. API Keys:  
        - Umbrella Investigate API token;  
        - ThreatGrid API token;  
        - CTR API Credentials;
6. Configure protected Network parameters:  
        - Protected network prefix (e.g. 10.0.0.0/8);  
        - Protected email domain (e.g. example.com);
        
**Used:** Python 2.7