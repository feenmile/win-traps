"""Fakes so matcher tests do not depend on the machine they run on."""

import os

from wintraps.catalog import Context

PROJ = os.path.normpath("/work/project")
SCRATCH = os.path.join(PROJ, "scratch")


def norm(path):
    return os.path.splitdrive(path)[1].replace("\\", "/")


class FakeFS:
    def __init__(self, *paths):
        self.paths = {norm(os.path.normpath(p)) for p in paths}

    def __call__(self, path):
        return norm(os.path.normpath(path)) in self.paths


class FakeGit:
    """Returns a fixed porcelain status and records each call."""

    def __init__(self, status):
        self.status = status
        self.calls = []

    def __call__(self, directory, options, paths):
        self.calls.append((directory, list(options), list(paths)))
        return self.status


def ctx(shell="bash", cwd=PROJ, git_status=None, which=None, exists=None, find_junctions=None, environ=None):
    return Context(
        shell=shell,
        cwd=cwd,
        git_status=git_status or FakeGit(None),
        which=which or (lambda name: None),
        exists=exists or FakeFS(),
        find_junctions=find_junctions or (lambda path: ([], True)),
        environ=environ if environ is not None else {},
    )
