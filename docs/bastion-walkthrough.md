# Building the bastion pattern with the tool

The lab builds this by hand in the AWS console. This does the same thing through
the provisioner, which changes two details worth noting in a write-up.

**The private keys are never downloaded from AWS.** The lab has AWS generate each
key pair and hand you a `.pem`. This tool refuses to call `CreateKeyPair` at all,
so `ssh-keygen` makes both halves on your machine and only the public half is
sent. The end result is identical for SSH; the difference is that no secret ever
crossed the network.

**Every instance requires IMDSv2.** This breaks the lab's Step 6 verification
command, on purpose. See the last section.

Everything below is free except the two instances, which are `t3.micro` and
free-tier eligible. Terminate them when finished.

---

## What you are building

```
                     your laptop
                          |  SSH on 22, from your address only
  ========================|=====================================
  |  network scp-xxxxxx   |                                    |
  |                       v                                    |
  |  +-- public subnet 10.0.1.0/24 --------------------------+ |
  |  |  route to internet gateway                            | |
  |  |                                                       | |
  |  |    bastion-host    public address                     | |
  |  |    group: bastion-sg                                  | |
  |  +-------------------------------------------------------+ |
  |                       |  SSH on 22, from bastion-sg only    |
  |                       v                                     |
  |  +-- private subnet 10.0.2.0/24 -------------------------+ |
  |  |  no route out at all                                  | |
  |  |                                                       | |
  |  |    private-instance    no public address              | |
  |  |    group: private-sg                                  | |
  |  +-------------------------------------------------------+ |
  ==============================================================
```

Two separate protections, and they fail differently, which is why both are
worth having.

`private-sg` trusts a *security group* rather than an address range. The
bastion's address can change and the rule keeps working, and nothing on the
internet can gain entry by arriving from the right address, because there is
no address to imitate.

The private *subnet* has no route to the internet gateway. That holds no matter
what anyone does to a machine inside it. Attach a public address to something
in the private subnet and it still cannot be reached, because the network has
nowhere to send the traffic. Do the same in a default VPC and the machine is
exposed the moment the address lands.

---

## 0. The network

```
python main.py
5 -> Networks
1 -> Create
```

Accept the generated name. You get a VPC, an internet gateway, a public subnet
routed through it, and a private subnet routed nowhere. Note both subnet IDs
from the table it prints.

The scan will report one finding: no flow logs, CIS 3.7. That is accurate and
left alone deliberately — enabling them means choosing somewhere to store logs
and paying for the storage, which is not a decision a tool should make for you.

No NAT gateway is created and the tool will refuse to make one. That is the
only thing in this exercise with a running cost, roughly $32 a month billed
from creation to deletion regardless of use, and nothing here needs it.

---

## 1. Two key pairs

```
python main.py
3 -> Key Pairs
1 -> Create a new key on this machine and register the public half
```

Name it `bastion-key`. Repeat for `private-key`.

Both private keys are written to `~/.ssh/` and never leave the machine.
`ssh-keygen` sets the permissions itself, so the lab's `chmod 400` step is
already done. These are ED25519 rather than the lab's RSA; both work, ED25519 is
shorter and faster.

## 2. The bastion's security group

```
1 -> Security Groups
1 -> Create
```

Name it `bastion-sg`, then add one rule:

- `[1] SSH - port 22`
- `[0] just this machine`

The tool detects your public address and writes a `/32` rule for it. Scan
result should be clean: SSH from a single address is not a finding.

## 3. The private group

Create `private-sg` with one rule:

- `[1] SSH - port 22`
- `[1] anything in another security group` -> pick `bastion-sg`

The scan reports this at informational level and says the arrangement is the
stronger one. That is the only place this tool tells you something is *right*,
which is why it is worth reading.

## 4. The bastion

```
4 -> Servers
1 -> Launch
```

- name `bastion-host`
- key pair `bastion-key`
- security group `bastion-sg`
- public address: **yes**

The tool warns that a public address makes the firewall rules the only thing in
the way. That is true and is the point of a bastion. Note the public address it
prints.

## 5. The private instance

Launch again:

- name `private-instance`
- key pair `private-key`
- security group `private-sg`
- public address: **no**

Note the private address. The scan should find nothing critical: the machine has
no route in from the internet, and the one rule that exists points at a group.

---

## 6. Connect

Add both keys to your agent:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/bastion-key
ssh-add ~/.ssh/private-key
```

Then reach the private instance in one command:

```bash
ssh -J ec2-user@<bastion-public-ip> ec2-user@<private-ip>
```

`-J` is ProxyJump. The lab's Step 5 uses `-A`, agent forwarding, instead. Prefer
`-J`: with `-A`, anyone with root on the bastion can use your forwarded agent
socket to authenticate as you to anything your loaded keys unlock, for as long
as you stay connected. The bastion is the most exposed machine you own, which
makes it the worst place to extend that trust. `-J` never exposes the agent to
it at all.

Both are better than copying a `.pem` onto the bastion, which the lab rightly
tells you not to do.

---

## 7. The part worth recording

On the private instance, run the lab's Step 6 verification command:

```bash
curl http://169.254.169.254/latest/meta-data/instance-id
```

It returns **401 Unauthorized**.

That command reads the instance's own metadata, which includes its AWS
credentials, over a plain unauthenticated request. It works on an instance
launched from the console with default settings. It fails here because this tool
sets `HttpTokens: required` at launch, so a request has to obtain a session
token first:

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id
```

The difference between those two commands is the difference an attacker can and
cannot exploit. A bug that makes an application fetch a web address chosen by
someone else will fetch the first one and hand over the credentials. It cannot
perform the second, because a forged request cannot issue a PUT and read back
the response. This is the mechanism behind the 2019 Capital One breach.

CIS AWS Foundations Benchmark v5.0.0 §5.7, Level 1, Automated.

---

## 8. Tear down

The whole thing, in one step:

```
python main.py
5 -> Networks
4 -> Delete one and everything inside it
```

It prints an inventory of everything that will be destroyed before asking, in
the order it will go, with a `!` beside anything the tool did not create
itself. Then it asks you to type the network's ID rather than pressing y.

That is deliberate friction. This is the only operation here that destroys
things you did not name — the machines inside the network go with it, and their
disks go with them. A yes/no prompt gets a reflexive yes; typing an ID does not.

Key pairs are not network resources and survive this. Remove them separately if
you want to:

```
3 -> Key Pairs -> 5
```

Or clear everything the tool has ever made, across all resource types:

```bash
python scripts/make_vulnerable.py --clean
```

The instances were the only things costing anything. Networks, subnets,
gateways, route tables, security groups and key pairs are all free.
