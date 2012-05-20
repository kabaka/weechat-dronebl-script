# WeeChat DroneBL Script

View, add, and remove listings on [DroneBL](http://dronebl.org/ Drone Blacklist)
with within WeeChat. An RPC key is required (get one
[here](http://dronebl.org/rpckey_signup)).

The code is in need of some rewriting. I coughed this up in a about half an hour
one afternoon and haven't really touched it since then. It works for me.

That said, there are some problems. If dronebl.org is down (which is often), the
script will block for about 30 seconds while it waits for a connection timeout.
If I ever get around to rewriting this in a more Rubyist, OOP style, I'll fix
that.

# To-do

* Move RPC key to a WeeChat setting.
* Fix long blocking time.
* Stick things in objects to simplify code.
* Clean up hackish code.
* Look-ups on /whois where a real IP is available (maybe).

