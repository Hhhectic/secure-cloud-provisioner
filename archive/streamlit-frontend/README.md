# The Streamlit frontend, kept but not used

This is a second, complete user interface for the tool, written against the
Azure half's API. It is not wired into anything and nothing imports it. It is
here because it works and because deleting a teammate's working interface on
the strength of one decision is not a decision anyone should have to take
twice.

## Why the group chose the other one

After the two halves were merged there were two frontends in `frontend/`, and
`frontend/app.py` sat beside `frontend/app.js` doing an entirely different job.
Only one can be the answer to "how do I use this", so:

| | This one | `frontend/` |
|---|---|---|
| Runs as | its own Streamlit process, its own port | served by the API itself at `/ui` |
| Talks to | `http://127.0.0.1:8000/api/v1`, the Azure routes | `/resources/...`, every resource type |
| Needs | `streamlit`, `requests`, and the Azure SDK | nothing — two script tags, no build step |
| Covers | Azure | both clouds, through one registry |

The deciding argument is the third row and the fourth. The served page needs no
process of its own, so a demonstration is one command rather than two, and it
reaches every registered resource type — including Azure, since Azure became a
`ResourceType`. This one would have needed its own half of the work rebuilt to
match.

None of that is a criticism of the code below. It was the right shape while the
Azure half was a separate application, which it was when this was written.

## Running it, if the decision is revisited

```bash
pip install streamlit requests
pip install -r requirements.txt        # the Azure SDK, for azure_deployer.py
streamlit run archive/streamlit-frontend/app.py
```

It expects the Azure API on port 8000 under `/api/v1`. Since the merge that
port serves `backend/api/app.py` instead, whose routes are `/resources/...`, so
`API_BASE_URL` in `app.py` would need changing before anything worked.

## One thing to know before reusing `azure_deployer.py`

It imports the Azure SDK at module scope and authenticates with
`DefaultAzureCredential`, which tries six credential sources in order and
succeeds with whichever it finds. That is convenient and it is why
`backend/az/common.py` deliberately does not use it: a tool that audits
whichever subscription happens to be lying around in the environment is one
that can audit the wrong subscription without saying so.
