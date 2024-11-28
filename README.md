ZFS snapshots are a great way of making backups. They are atomic, making it possible to take snapshots of database servers without corruption. They are also fast and storage-efficient. When using ZFS native encryption to encrypt datasets locally, a "raw send" can be used to only send encrypted data off-site.

If you know someone who also uses ZFS, sending ZFS snapshots to each other is a cost-effective backup solution. However, the straight-forward setup requires SSH with root access to their server! Server owners who value their data enough to run ZFS with native encryption, probably don't like the idea of giving someone else administrative privileges on their server.

This repository provides guidance and tools to allow giving a third party SSH access, that can only be used for specific ZFS operations in specific datasets.

## Creating a user

Start by creating a user: `useradd <user>`

## ZFS privilege delegation

Create a parent dataset for receiving backups, for example: `zfs create yourpool/<user>_backup`

The newly created user can now be given permission to create and modify datasets within this parent dataset.

```
zfs allow <user> create,receive,mount,destroy,rollback,hold,release yourpool/<user>_backup
```

## Command restriction

Download the `restrict_zfs.py` script from this repository and place it in the user's PATH, or alternately in `/usr/local/bin` for it to be available to all users.

```
wget https://raw.githubusercontent.com/Derkades/ssh-zfs-receive/main/restrict_zfs.py
mkdir -p ~user/.local/bin
mv restrict_zfs.py ~user/.local/bin/
chown user: ~user/.local/bin/restrict_zfs.py
chmod +x ~user/.local/bin/restrict_zfs.py
```

Now, allow SSH access by placing the other party's public key in `.ssh/authorized_keys`. However, configure SSH to always run this Python script instead of the user's command:

```
restrict,command="restrict_zfs.py" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHpe6qcB6U4kIatI+4CY3AKcvEoapDbKZklbRcr4QR7D
```

The Python script will verify the original SSH command to make sure it is a command that would be executed by a tool like Syncoid. If the command seems fine, it runs the command as usual without the client noticing. Otherwise, the command is blocked and logged to syslog.

## Running syncoid

Run syncoid with `--no-privilege-elevation` otherwise it will not work, as it will try to add `sudo` to all remote zfs commands. Since zfs delegation gives the non-root user permission to manage its own dataset(s), sudo is unnecessary and should not be configured. Other options can be used as usual with no changes.

Some commands are untested, in particular all "remote source" operations. Remote destination operations are tested and should work, including `--use-hold`, `--insecure-direct-connection` and `--recvoptions`.

Please report any blocked commands and they will be added to the script if necessary!

## Command help
```
usage: restrict_zfs.py [-h] [--dry-run] [--verbose] [--log [{syslog,stderr} ...]]

options:
  -h, --help            show this help message and exit
  --dry-run             do not run any commands, log commands regardless of --verbose
  --verbose             log allowed commands, instead of only failed commands
  --log [{syslog,stderr} ...]
                        log destination (zero, one, or multiple may be specified)
```

## Security warning

This script only performs best-effort parsing of commands using regular expressions. The intention is to make it harder for an attacker to run malicious commands on a backup server. It may not be entirely safe. You are invited to investigate the source code for any potential flaws.

The intention of this script is not to protect your backups. `zfs destroy` and `zfs rollback` are allowed by default, so an attacker could delete all backups. It is only meant to protect other users or other applications on the remote system.
