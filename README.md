ZFS snapshots are a great way of making backups. They are atomic, making it possible to take snapshots of database servers without corruption. They are also fast and storage-efficient. When using ZFS native encryption to encrypt datasets locally, a "raw send" can be used to only send encrypted data off-site.

If you know someone who also uses ZFS, sending ZFS snapshots to each other is a cost-effective backup solution. However, the straight-forward setup requires SSH with root access to their server! Server owners who value their data enough to run ZFS with native encryption, probably don't like the idea of giving someone else administrative privileges on their server.

This repository provides guidance and tools to allow giving a third party SSH access, that can only be used for specific ZFS operations in specific datasets.

## Creating a user

Start by creating a user: `useradd <user>`

## ZFS privilege delegation

Create a parent dataset for receiving backups, for example: `zfs create yourpool/<user>_backup`

The newly created user can now be given permission to create and modify datasets within this parent dataset.

```
zfs allow <user> create,receive,mount,destroy,rollback yourpool/<user>_backup
```

## Command restriction

Download the `restrict_zfs.py` script from this repository and place it in the user's home directory.

```
wget https://raw.githubusercontent.com/Derkades/ssh-zfs-receive/main/restrict_zfs.py
```

Now, allow SSH access by placing the other party's public key in `.ssh/authorized_keys`. However, configure SSH to always run this Python script instead of the user's command:

```
restrict,command="python3 restrict_zfs.py" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHpe6qcB6U4kIatI+4CY3AKcvEoapDbKZklbRcr4QR7D
```

The Python script will verify the original SSH command to make sure it is a command that would be executed by a tool like Syncoid. If the command seems fine, it runs the command as usual without the client noticing. Otherwise, the command is blocked and logged to syslog.
