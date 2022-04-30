# Lonk

A very simple link shortener, written in Rust, made to self host.

## Serving lonk

`lonk` can be served with `docker-compose` (recommended) or as a binary.

### Serving with `docker-compose`

Serving `lonk` with `docker-compose` is trivial: pull the repository to a chosen
location...

```
mkdir /etc/lonk
git clone https://git.cumperativa.xyz/meeg_leeto/lonk /etc/lonk
```

... and serve:

```
cd /etc/lonk && docker-compose up
```

By default, this will serve `lonk` on `localhost:8892`. You can change this port in
`docker-compose.yml`. Likewise, you may adjust other parameters in `data/config.json`.

Mind that some of these parameters correspond to the container; so, in particular,
you should not change the port or database location in `config.json`, unless you make the
corresponding changes in `docker-compose.yml`. (If you are unfamiliar with
`docker-compose`, just leave these parameters alone; they do not affect your system in any
way.)

### Serving as a binary

**Please make sure you know what you are doing.**

> Although I've tried my best for `lonk` to be correct, I cannot guarantee its safety.
> Using containerization will provide (at least) some level of extra security, in case
> `lonk` is exploitable. By running `lonk` directly as an executable, you are removing a
> layer between a potential attacker and your system.

To run `lonk` as a binary, preferably create a dedicated user and directory:

```
root# useradd --no-create-home --disabled-login lonk
root# mkdir /etc/lonk
root# chown lonk:lonk /etc/lonk
```

... place the lonk executable in that directory...

```
root# mv lonk /etc/lonk/lonk
root# chown lonk:lonk /etc/lonk/lonk
```

... and then run the `lonk` executable as this user. Configuring `lonk` is done the same
as in the `docker-compose` case, namely by creating the appropriate `config.json`;
for a starting point, run `lonk --print-default-config`:

```
root# sudo -i lonk /bin/bash
lonk$ mkdir /etc/lonk/served
lonk$ /etc/lonk/lonk --print-default-config > etc/lonk/lonk.json
```

You may set a different configuration file by setting the environment variable
`LONK_CONFIG`.

You will have to have [Redis](https://en.wikipedia.org/wiki/Redis) running and listening
on the port specified in the configuration file. Also, if you don't want to write your
own HTTP frontend, you'll have to copy the contents of the `data` directory from
the repository into the newly created `/etc/lonk/served` directory. (Don't forget to
`chown lonk:lonk` the copied contents.)

(The frontend is quite minimalist, and I encourage you to look at `main.js` and write
your own.)

Finally, serve `lonk` (in the location specified in the configuration file):

```
lonk$ logout
root# sudo -i lonk /etc/lonk/lonk
```

## Contributing

Pull requests are welcome. Issues are not guaranteed to be addressed. `lonk` is
built primarily for self-use, provided to you for free, and not my primary
occupation. Please respect this.

## Licence

`lonk` is licenced under a GNU General Public License, version 3. This
[**informally**][GPLv3] means that:

> You may copy, distribute and modify the software as long as you track
> changes/dates in source files. Any modifications to or software including (via
> compiler) GPL-licensed code must also be made available under the GPL along with
> build & install instructions.

You can find a copy of the licence under `LICENCE`.

## Support

Getting donations, no matter how small, lets me know that people use and
appreciate the software I've published.

💕 If you like and use `lonk`, consider
[buying me a coffee](https://www.paypal.me/miguelmurca/2.50).

[GPLv3]: https://tldrlegal.com/license/gnu-general-public-license-v3-(gpl-3)