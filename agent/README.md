# Control agent deployment

`Agent Deploy` updates the public `AgentWorkforce/relay-control` lead's prompt
and host guardrails on the existing Control instance in sessions-dev/us-west-2.
It requires the existing native supervisor and pinned conversation. EC2,
CloudFormation ownership, application releases and secret values are unchanged.

The workflow is manual and runs only from `main`, through the `agent-deploy`
Environment. Configure that Environment to permit only the `main` branch.
The deploy role's exact immutable GitHub subject and policy are in `iam/`.
Its sole write capability is root SSM command execution on the existing Control
instance; it cannot create/reboot/replace instances or change IAM or secrets.
Set repository variable `LAYERED_CONTROL_AGENT_DEPLOY_ROLE_ARN` to that role.
Provisioning this role is a separate, explicitly approved IAM operation.

```sh
gh workflow run agent-deploy.yml --repo AgentWorkforce/relay-control --ref main
```

The host must be SSM-online first. An unreachable guest fails preflight without
sending a deployment command. A submitted command is polled by its existing ID;
a failure or timeout never causes an automatic second submission.

The lead service and the agent user's other processes each have `MemoryHigh=6G`
and `MemoryMax=8G`, leaving at least 16 GiB of a 32 GiB host outside those two
budgets. The deployment refuses to impose a budget already exceeded. All heavy
jobs use `layered-heavy COMMAND ...`, sharing one `flock` across the host.
The lead's service restarts on unexpected exit, with its existing start-rate
limit and pinned native conversation. Deployment itself does not restart it.
The new lane prompt is delivered as one stable, attributed native task.

These controls isolate agent workloads; application/database limits and memory,
OOM, EC2 status, SSM and Relay-heartbeat alerts also need operator review. The
successful deployment receipt is not proof that those other services are healthy.

For a new host, use the shared layered-agent component and provisioning workflow
in https://github.com/AgentWorkforce/layered-agents. This workflow targets the
already deployed Control host and does not adopt its CloudFormation stack.

Validate without cloud calls:

```sh
python3 -m unittest discover -s agent/test -v
```
