import os
import re
import syslog
import sys
import subprocess

POOL = r"'[\w-]+'"
DATASET = r"'[\w\/-]+'"
DATASET_SNAPSHOT = r"'[\w/-]+'@'[\w:-]+'"

# Used when syncoid calls zfs destroy -- ONLY snapshots that match this regex will be allowed to be destroyed.
# Note: Syncoid does NOT single quote the snapshot name as of version 2.1.0, but let's allow that.
SYNCOID_SNAPSHOT = r"'[\w/-]+'@('?)syncoid_[\w:-]+\1"

# These commands were issued by Syncoid with standard options. If in your
# usage you notice any commands that should be allowed but aren't allowed
# here, please contribute!
ALLOWED_COMMANDS = [
    r'exit',
    r'echo -n',
    r'command -v (lzop|mbuffer)',
    r'zpool get -o value -H feature@extensible_dataset ' + POOL,
    r'ps -Ao args=',
    r'zfs get -H (name|receive_resume_token) ' + DATASET,
    r'zfs get -Hpd 1 -t snapshot guid,creation ' + DATASET,
    r'zfs get -H -p used ' + DATASET,
    r'lzop -dfc \|  zfs receive  -s -F ' + DATASET,
    r'lzop -dfc \|  zfs receive  -s -F ' + DATASET + r' 2>&1',
    # If syncoid --no-sync-snap is *not* used, the following line may work with SYNCOID_SNAPSHOT
    # instead of DATASET_SNAPSHOT to be more restrictive
    r'zfs rollback -R ' + DATASET_SNAPSHOT,
    r'mbuffer (-r \d+[kM])? -q -s \d+[kM] -m \d+[kM] 2>\/dev\/null \| lzop -dfc \|  zfs receive  -s (-F)? ' + DATASET,
    r'mbuffer (-r \d+[kM])? -q -s \d+[kM] -m \d+[kM] 2>\/dev\/null \| lzop -dfc \|  zfs receive  -s (-F)? ' + DATASET + ' 2>&1',
    r'zfs destroy ' + SYNCOID_SNAPSHOT,
]

COMPILED = [re.compile(command) for command in ALLOWED_COMMANDS]


def check_allowed(command: str):
    for allowed in COMPILED:
        if allowed.fullmatch(command):
            return True

    return False


if __name__ == '__main__':
    original_command = os.environ['SSH_ORIGINAL_COMMAND']

    # Syncoid can send multiple destroy commands separated by a semicolon when pruning.
    # Split them so that we can validate each command on its own.
    commands = original_command.split(';')

    for command in commands:
        command = command.strip()
        is_allowed = check_allowed(command)
        if not is_allowed:
            syslog.syslog('blocked command: ' + command)
            sys.exit(1)

        command2 = ['sh', '-c', command]
        syslog.syslog('running command: ' + str(command2))
        subprocess.run(command2)
