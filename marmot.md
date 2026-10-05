A browser based signal protocol messanger.
User data and chats will be stored in encrypted sql servers.
The server will eventually run in an elastic beanstalk unlike rattunnel, but this should be one of the last steps.
There should also be a feature called discord link which will be added next, which allows people on Marmot to chat with people on specific discord servers which install the Marmot discord bot.

There will still be a voice chat feature, which is end to end encrypted  using strp.

Users can find other  uses either if the user turned on global discovery (default off), to which they can be discovered in the peers tab under the global section.
Users can also find eachother if they know eachother's  usernames, to which they can friend eachother in peers and message.

The client, like RatTunnel, should run in a standalone html file for portability.



The order of things to implement should look like:

1. basic functionality of signal protocol and account data
2. peers system
3. discord link
4. voicechat
5. finishing touches
6. launch to eb and test