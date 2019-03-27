#!/bin/env python

from datetime import datetime
import logging
import os
import re
import shutil
import subprocess
import sys
import traceback

os.environ["PAGURE_CONFIG"] = "/etc/pagure/pagure.cfg"

import pygit2

from pagure.config import config as pagure_config
from pagure.lib.query import create_session, get_repotypes
from pagure.lib.model import Project


def runcmd(workdir, cmd, env=None, mayfail=False):
    """ Execute a command as a subprocess. """
    logging.debug("Running %s in workdir %s", cmd, workdir)
    func = subprocess.check_call
    if mayfail:
        func = subprocess.call
    if env:
        newenv = os.environ.copy()
        newenv.update(env)
        env = newenv
    func(
        cmd,
        cwd=workdir,
        env=env,
    )


def repospanner_clone(project, repotype, set_config, target):
    """ Create a clone of a repoSpanner repo to filesystem.

    """
    repourl, regioninfo = project.repospanner_repo_info(repotype)

    command = [
        "git",
        "-c",
        "protocol.ext.allow=always",
        "clone",
        "ext::%s %s"
        % (
            pagure_config["REPOBRIDGE_BINARY"],
            project._repospanner_repo_name(repotype),
        ),
        target,
    ]
    environ = os.environ.copy()
    environ.update(
        {
            "USER": "pagure",
            "REPOBRIDGE_CONFIG": ":environment:",
            "REPOBRIDGE_BASEURL": regioninfo["url"],
            "REPOBRIDGE_CA": regioninfo["ca"],
            "REPOBRIDGE_CERT": regioninfo["push_cert"]["cert"],
            "REPOBRIDGE_KEY": regioninfo["push_cert"]["key"],
        }
    )
    subprocess.check_call(
        command, env=environ
    )

    repo = pygit2.Repository(target)
    if set_config:
        repo.config["repospanner.url"] = repourl
        repo.config["repospanner.cert"] = regioninfo["push_cert"]["cert"]
        repo.config["repospanner.key"] = regioninfo["push_cert"]["key"]
        repo.config["repospanner.cacert"] = regioninfo["ca"]
        repo.config["repospanner.enabled"] = True
    return repo


def prime_cache(project):
    """ Build or update the Pagure pseudo cache. """
    logging.info("Priming cache for %s at %s", project.fullname, datetime.utcnow())

    pseudopath = pagure_config["REPOSPANNER_PSEUDO_FOLDER"]

    for repotype in get_repotypes():
        logging.info("Pulling repotype %s", repotype)
        currentdir = project.repopath(repotype)
        if currentdir is None:
            logging.info("Repotype not in use, skipping")
            continue
        cachedir = os.path.join(pseudopath, repotype, project.path)

        # Clone
        tempdir = cachedir + '.cacheprime'
        repospanner_clone(project, repotype, True, tempdir)

        if os.path.exists(cachedir):
            if os.path.exists(cachedir + ".old"):
                raise Exception("Error: old cachedir already existed: %s.old" % cachedir)
            os.rename(cachedir, cachedir + ".old")
        os.rename(tempdir, cachedir)
        shutil.rmtree(cachedir + ".old")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: %s <project-match>" % sys.argv[0])

    logging.basicConfig(level=logging.INFO)

    matcher = re.compile(sys.argv[1])

    session = create_session(pagure_config["DB_URL"])

    query = session.query(Project).filter(Project.repospanner_region!=None)

    logging.info("Starting processing")
    for project in query:
        if not matcher.match(project.fullname):
            logging.debug(
                "Skipping project %s due to no match", project.fullname)
            continue
        try:
            prime_cache(project)
        except Exception:
            traceback.print_exc()


if __name__ == '__main__':
    main()
