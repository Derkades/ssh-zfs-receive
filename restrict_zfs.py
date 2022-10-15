import os
import re
import syslog
import sys


POOL = r"'[a-z0-9_-]+'"
DATASET = r"'([a-z0-9_-]+\/?)+'"
DATASET_SNAPSHOT = r"'([a-z0-9_-]+\/?)+'@'[a-z0-9:_-]+'"

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
    r' lzop -dfc \|  zfs receive  -s -F ' + DATASET,
    r' lzop -dfc \|  zfs receive  -s -F ' + DATASET + r' 2>&1',
    r' zfs rollback -R ' + DATASET_SNAPSHOT,
    r' mbuffer (-r \d+[kM])? -q -s \d+[kM] -m \d+[kM] 2>\/dev\/null \| lzop -dfc \|  zfs receive  -s -F ' + DATASET,
    r' mbuffer (-r \d+[kM])? -q -s \d+[kM] -m \d+[kM] 2>\/dev\/null \| lzop -dfc \|  zfs receive  -s -F ' + DATASET + ' 2>&1',
]

COMPILED = [re.compile(command) for command in ALLOWED_COMMANDS]


def check_allowed(command: str):
    for allowed in COMPILED:
        if allowed.fullmatch(command):
            return True

    return False


if __name__ == '__main__':
    command = os.environ['SSH_ORIGINAL_COMMAND']

    is_allowed = check_allowed(command)
    if not is_allowed:
        syslog.syslog('blocked command: ' + command)
        sys.exit(1)

    command2 = ['sh', '-c', command]
    syslog.syslog('running command: ' + str(command2))
    os.execlp(command2[0], *command2)
