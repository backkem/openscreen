# Presentation API Demo

This directory contains a demo of a Presentation API controller and receiver.
The demo supports flinging a URL to start a presentation and stopping the
presentation.

## Command line options

The same executable is run for the controller and receiver; only the command
line options affect the behavior.  The command line options are:

``` bash
    $ osp_demo [-v] [friendly_name]
```

 - `-v` enables verbose logging.
 - Specifying `friendly_name` puts the demo in receiver mode and sets its name
   to `friendly_name`.  If no friendly name is given, the demo runs as a controller.

## Log output

Because the demo acts like a shell and accepts commands on `stdin`, the logging
output is redirected to a separate file so it doesn't flood the same display.
You have to create these files on your machine before running the demo.  For the
controller, this file should be named `_cntl_fifo` and for the receiver, it
should be named `_recv_fifo`.  The simplest way to do this is so you can see the
output while the demo is running is to make these named pipes like so:

``` bash
    $ mkfifo _cntl_fifo _recv_fifo
```

Then `cat` them in separate terminals while the demo is running.

## Listener commands

 - `connect <instance_name>`: Build a connection to receiver named `instance_name`.
   All connectable receivers are discovered by discovery module and printed in the
   output log.
 - `avail <url>`: Begin listening for all connected receivers that support the
   presentation of `url`.
 - `start <url> <instance_name>`: Start a presentation of `url` on the receiver
   specified by the `instance_name`.  `instance_name` will be printed in the output
   log once `avail` has been run.  The demo only supports starting one
   presentation at a time.
 - `msg <string>`: Sends a string message on the open presentation connection.
 - `close`: Close the open presentation connection without terminating the
   presentation.
 - `reconnect`: Reconnect the previously-connected presentation connection.
   This allows using the `msg` command again.
 - `term`: Terminate the previously started presentation.

## Publisher commands

 - `avail`: Toggle whether the receiver is publishing itself as an available
   screen.  The receiver starts in the publishing state.
 - `close`: Close the open presentation connection without terminating the
   presentation.
 - `msg <string>`: Sends a string message on the open presentation connection.
 - `term`: Terminate the running presentation.

## Interactive Terminal UI

For convenience, an interactive curses-based split-screen terminal UI wrapper is
provided in `osp_demo_ui.py`. It automatically manages the named pipes (`FIFOs`)
and displays logs in a scrolling top pane while providing an interactive command
prompt in the bottom pane.

Run Controller mode:
``` bash
$ python3 osp/demo/osp_demo_ui.py
```

Run Receiver mode:
``` bash
$ python3 osp/demo/osp_demo_ui.py DemoReceiver
```

Optional arguments:
 - `-o, --out-dir`: Path to build output directory relative to repo root (e.g. `out/Default`).
 - `-b, --binary`: Explicit path to `osp_demo` executable.

## Testing & Verification

Whenever modifying demo code or underlying OSP protocols, verify that demo startup
and command handling pass the smoke test:

``` bash
$ python3 osp/demo/osp_demo_smoke_test.py [path/to/osp_demo]
```
If omitted, the test defaults to `./out/Default/osp_demo`.


## lp2p_demo (experimental)

`lp2p_demo` exercises the data channel extension of the
[Local Peer-to-Peer API](https://wicg.github.io/local-peer-to-peer/) on top of
OSP, with `Lp2pReceiver`/`Lp2pRequest` from `osp/public/lp2p/`. One side
advertises and echoes text messages; the other discovers it, opens a data
channel and sends the lines it reads from stdin. Run each side in a directory
that contains `osp/impl/quic/certificates/`:

``` bash
$ out/Default/lp2p_demo --spake2_suite=p256 --psk=123456 --listen=MyPeer
$ out/Default/lp2p_demo --spake2_suite=p256 --psk=123456 --connect=MyPeer
hello
lp2p_demo: received on 0 (string): echo: hello
```

The same commands work against go-lp2p (`openscreen-go`), which needs only the
matching P-256 opt-in.
