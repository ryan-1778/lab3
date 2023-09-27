#!/usr/bin/env python

import gzip
import os
import sys

import networkx as nx

def is_syscall(line):
    """Returns True if the line is a syscall message."""
    return line.startswith("type=SYSCALL")

def parse_syscall(line):
    """Parses a SYSCALL message, returning a dictionary."""
    assert is_syscall(line)
    data = dict()
    pairs = line.strip().split(' ')[:26]
    for pair in pairs:
        key, val = pair.split('=', 1)
        data[key] = val
    return data

def is_execve(line):
    """Returns True if the line is an execve message."""
    return line.startswith("type=EXECVE")

def parse_execve(line):
    """Parses an EXECVE message, returning a dictionary."""
    assert is_execve(line)
    data = dict()
    pairs = line.strip().split(' ')
    for pair in pairs:
        key, val = pair.split('=', 1)
        data[key] = val
    return data

def is_path(line):
    """Returns True if the line is a path message."""
    return line.startswith("type=PATH")

def parse_path(line):
    """Parses a PATH message, returning a dictionary."""
    assert is_path(line)
    data = dict()
    pairs = line.strip().split(' ')[:11]
    for pair in pairs:
        key, val = pair.split('=', 1)
        data[key] = val
    return data

def is_cwd(line):
    """Returns True if the line is a cwd message."""
    return line.startswith("type=CWD")

def parse_cwd(line):
    """Parses a CWD message, returning a dictionary."""
    assert is_cwd(line)
    data = dict()
    pairs = line.strip().split(' ')
    for pair in pairs:
        key, val = pair.split('=', 1)
        data[key] = val
    return data

def parse_line(line):
    """Parses a line, returning a dictionary on success,
    or None if there's no parser for this message type."""
    if is_syscall(line):
        return parse_syscall(line)
    elif is_execve(line):
        return parse_execve(line)
    elif is_path(line):
        return parse_path(line)
    elif is_cwd(line):
        return parse_cwd(line)
    else:
        return None

def parse_events(audit_fp):
    """Parses an audit log into a dictionary where the key
    is an event ID (integer) and the value is a list of
    messages for that event."""
    events = dict()

    with gzip.open(audit_fp, 'rt') as ifile:
        for line in ifile:
            data = parse_line(line)
            if data is None:
                continue

            eid = int(data['msg'].split(":")[1][:-1])

            if not eid in events:
                events[eid] = list()

            events[eid].append(data)

    return events

def build_graph(graph, events):
    # TODO: Insert your code here!

def main():
    if len(sys.argv) != 3:
        print("Usage: %s <audit.log.gz> <output.dot>" % os.path.basename(sys.argv[0]))
        sys.exit(1)

    events = parse_events(sys.argv[1])
    graph = nx.DiGraph()

    build_graph(graph, events)

    print("Saving graph to: %s" % sys.argv[2])
    nx.drawing.nx_pydot.write_dot(graph, sys.argv[2])

if __name__ == "__main__":
    main()
