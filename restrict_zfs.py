#!/usr/bin/env python3
import os
import re
import syslog
import sys
import subprocess

POOL = r"'[\w-]+'"
DATASET = r"'[\w\/-]+'"
DATASET_SNAPSHOT = r"'[\w/-]+'@'[\w:-]+'"

# Note: Syncoid does NOT single quote the snapshot name as of version 2.1.0, but let's allow that.
SYNCOID_SNAPSHOT = r"'[\w/-]+'@('?)syncoid_[\w:-]+\1"

SYNCOID_HOLD = r"[\w]+"

REDIRS = r'(?:\s+(?:2>/dev/null|2>&1))?'
PIPE = r'\s*\|\s*'
MBUFFER_CMD = r'mbuffer (?:-[rR] \d+[kM])? (?:-W \d+ -I [\w.:-]+ )?-q -s \d+[kM] -m \d+[kM]'
NC_CMD = r'busybox nc -l [\w.:-]+ -w \d+'
MBUFFER_OR_NC_CMD = r'(?:' + MBUFFER_CMD + r'|' + NC_CMD + r')'
SOCAT_CMD = r'socat - TCP:[\w.:-]+,retry=\d+,interval=1'
COMPRESS_CMD = r'(?:(?:gzip -3|zcat|pigz -(?:\d+|dc)|zstd -(?:\d+|dc)|xz(?: -d)?|lzop(?: -dfc)?|lz4(?: -dc)?)\s*\|)?'

ZFSPROP = r'[a-z0-9:._-]+=[a-z0-9:._-]*'
ZFSPROPS = r'(?:-o ' + ZFSPROP + r'\s+)*'
SHORTOPTS = r'(?:-[A-Za-z0-9]+\s+)*'

# These commands were issued by Syncoid with standard options. If in your
# usage you notice any commands that should be allowed but aren't allowed
# here, please contribute!
ALLOWED_COMMANDS = [
    r'exit',
    r'echo -n',
    r'command -v (?:gzip|zcat|pigz|zstd|xz|lzop|lz4|mbuffer|socat|busybox)',
    r'zpool get -o value -H feature@extensible_dataset ' + POOL,
    r'ps -Ao args=',
    r'zfs get -H (?:name|receive_resume_token|-p used|syncoid:sync) ' + DATASET + REDIRS,
    r'zfs get -Hpd 1 (?:-t (?:snapshot|bookmark) |type,)guid,creation ' + DATASET + REDIRS,
    r'zfs get all -s local -H ' + DATASET,
    r'zfs list -o name,origin -t filesystem,volume -Hr ' + DATASET,
    # If syncoid --no-sync-snap is *not* used, the following line may work with SYNCOID_SNAPSHOT
    # instead of DATASET_SNAPSHOT to be more restrictive
    r'zfs rollback -R ' + DATASET_SNAPSHOT,
    MBUFFER_OR_NC_CMD + PIPE + COMPRESS_CMD + r'\s*zfs receive\s+' + SHORTOPTS + ZFSPROPS + DATASET + REDIRS,
    r'zfs receive -A '+ DATASET,
    r'zfs send\s+' + SHORTOPTS + r'(?:-t [0-9a-f-]+|-[iI] ' + DATASET_SNAPSHOT + r'(?: ' + DATASET_SNAPSHOT + r')?)' + REDIRS + r'(?:' + PIPE + MBUFFER_CMD + r'(?:' + PIPE + SOCAT_CMD + r')?)?',
    r'zfs snapshot ' + SYNCOID_SNAPSHOT,
    # the script used to only allow destroying SYNCOID_SNAPSHOT but using --no-sync-snap it wanted to destroy "autosnap" snaps
    # loosening the restriction should be safe IF zfs delegation is used with a non-root user (SHOULD be mandatory for security)
    r'zfs destroy ' + DATASET_SNAPSHOT,
    r'zfs hold ' + SYNCOID_HOLD + r'\s+' + DATASET_SNAPSHOT,
    r'zfs release ' + SYNCOID_HOLD + r'\s+' + DATASET_SNAPSHOT,
]

COMPILED = [re.compile(command) for command in ALLOWED_COMMANDS]


def check_allowed(command: str):
    for allowed in COMPILED:
        if allowed.fullmatch(command):
            return True

    return False


if __name__ == '__main__':
    dryrun = False
    tostderr = False
    tosyslog = True
    original_command = os.environ['SSH_ORIGINAL_COMMAND']

    # Syncoid can send multiple destroy commands separated by a semicolon when pruning.
    # Split them so that we can validate each command on its own.
    commands = original_command.split(';')

    for command in commands:
        command = command.strip()
        command2 = ['sh', '-c', command]

        is_allowed = check_allowed(command)
        if not is_allowed:
            errtext = 'blocked command: ' + command
        elif dryrun:
            errtext = 'would run command (dry run): ' + str(command2)
        else:
            errtext = 'running command: ' + str(command2)

        if tostderr:
            print(errtext, file=sys.stderr)
        if tosyslog:
            syslog.syslog(errtext)

        if not is_allowed:
            sys.exit(1)
        elif not dryrun:
            subprocess.run(command2)
