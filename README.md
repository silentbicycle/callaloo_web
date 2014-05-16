Minimal web server for publishing current callaloo status (via MQTT).

Approaching RFC 2616-compliance, but not there yet. Don't run this
exposed to the internet! It's intended run in a controlled environment,
serving data from a sensor network project of mine, and only accepts a
small set of whitelisted inputs.


### Architecture

This server forks a new process to handle each request and response,
which closes the socket after the response is sent. This works well
enough for this application, which is unlikely to serve more than a few
concurrent clients.

It's currently missing logging, and the error handling is not robust --
it should be run under a process supervisor, such as [daemontools] or
[runit]. But, hey, it's only about 400 lines of C.

[daemontools]: http://cr.yp.to/daemontools.html
[runit]: http://smarden.org/runit/


### Endpoints served:

+ /

This returns the status of the upstairs and downstairs doors, in
`text/plain` format.

+ /json


This returns the status of the upstairs and downstairs doors, in
`text/json` format, e.g.:

    {
        "downstairs": "open",
        "upstairs": "closed"
    }
    
    
+ /upstairs

Like `/`, but upstairs only.

+ /downstairs

Like `/`, but downstairs only.


### MQTT subscriptions

Messages published at `callaloo/upstairs` and `callaloo/downstairs`
update the current state.
