"""Shared SDK access for the AWS modules. The mirror of `az/common.py`.

This file exists so that importing `aws/` costs nothing on a machine without
boto3, the same way importing `az/` costs nothing without the Azure SDK.

`api/registry.py` imports every provider module at startup. Until this file
existed, `aws/*.py` imported boto3 at module scope, so a checkout without it
could not import `api/app.py` at all - the whole page, both clouds, refused to
start over a missing dependency for one of them. That was the exact objection
already recorded against the Azure half, and it was true in the other direction
the entire time.

Two things are needed to make an `aws/` module import-safe:

    client()      builds a boto3 client, importing boto3 at call time
    ClientError   and its two siblings, importable whether or not botocore is

The exceptions are the awkward half. `except ClientError` has to name something
at import time, so when botocore is absent they resolve to placeholder classes
that nothing ever raises. That is sound rather than a trick: without botocore
no AWS call can be made - `client()` refuses first - so no `except` clause
naming one of these can ever be reached.
"""


# What a caller sees when boto3 is absent. Deliberately not an ImportError,
# for the reason az/common.py gives: the routes turn this into a sentence
# about what to install, and a traceback about a module nobody using the tool
# has heard of is not something they can act on.
class AwsNotConfigured(Exception):
    """boto3 is not available in this process."""


INSTALL_HINT = (
    "The AWS half needs boto3, which this installation does not have. Run "
    "`pip install -r backend/requirements.txt`."
)


try:
    from botocore.exceptions import BotoCoreError, ClientError, WaiterError
    SDK_PRESENT = True
except ImportError:  # pragma: no cover - exercised by the subprocess tests
    SDK_PRESENT = False

    # Named the same and never raised. Every path that could raise one goes
    # through client(), which refuses before any call is made.
    class BotoCoreError(Exception):
        """Placeholder for botocore's, used when botocore is not installed."""

    class ClientError(BotoCoreError):
        """Placeholder for botocore's, used when botocore is not installed."""

    class WaiterError(BotoCoreError):
        """Placeholder for botocore's, used when botocore is not installed."""


def client(service, region=None):
    """Builds a boto3 client, or explains why it cannot.

    boto3 is imported here rather than at module scope. See the module
    docstring: a module-level import would make boto3 a hard requirement of
    starting the process, which is what this file was written to end.
    """
    try:
        import boto3
    except ImportError as e:
        raise AwsNotConfigured(f"{INSTALL_HINT} ({e})") from e

    return boto3.client(service, region_name=region)


def enabled_regions(region=None):
    """Every region this account can actually use, newest answer each call.

    Asked of EC2 rather than hardcoded, because a hardcoded list is wrong in
    both directions: it goes stale as AWS opens regions, and it names regions
    an account has not opted into, so a sweep over it reports "could not check"
    for places that were never available. `describe_regions` without
    AllRegions answers exactly the set this account may call.

    Raises rather than falling back to [region]. A sweep that quietly became a
    single-region check would let a finding claim it looked everywhere when it
    looked in one place, which is the reassuring-answer failure this project
    spends `unreadable` on preventing. The caller decides what to say about a
    sweep it could not perform.
    """
    ec2 = client("ec2", region)
    found = ec2.describe_regions()["Regions"]
    return sorted(r["RegionName"] for r in found)
