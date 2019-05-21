# bitcoin-crawler

This is a tool for studying the block propagation patterns of blocks on the Bitcoin network.

Built for my [masters thesis](https://bitcoin.aapelivuorinen.com/).

## Installation

You'll need Python 3, and `virtualenv`. Then do:

```sh
virtualenv . -p python3
source bin/activate
pip install -r requirements.txt
python client.py
```

If you don't have IPv6, change the line with `ENABLE_IPV6 = True` to `ENABLE_IPV6 = False`.

## Help

If you're having trouble with using this, I'd like to help you out. Either open an issue on GitHub, or email me at the email address on my website!