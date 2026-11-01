# Torn Raffles

**by Xerra [2775419]**

Prize wheels, raffles and other events for a [Torn](https://www.torn.com) faction, with a public log so every member can see that nothing was rigged.

The site: https://lordxerra.github.io/Torn-Raffles/

## Signing in

Use your own API key. A **Public** key is all that's needed, as the site only asks Torn who you are and which faction you're in. People outside the admin's faction are refused.

Your browser remembers the key until you sign out. The server uses it at sign-in to check with Torn and then discards it without storing it.

## Roles

| Role | Can do |
|---|---|
| **Admin** | Everything, including setting anyone to Planner or Member. Only Xerra. |
| **Planner** | Set up events, including choosing who is included. |
| **Member** | View events and the log. |

Everyone starts as a Member. Anyone who leaves the faction loses access and their role.

## Spin the Wheel

The wheel shows every ticked member. A Planner or the Admin fills in up to 10 prizes and presses Spin, and the wheel spins once per prize, in order, stopping on that prize's winner.

The server draws all the winners and writes them to the log the moment Spin is pressed. The wheel only reveals that result, so a draw can't be stopped or re-rolled.

## How it's built

- `index.html` is the whole site, served by GitHub Pages.
- `server/` is a small Flask API on the NAS, because GitHub Pages can't hold shared data or check permissions. It's published through DSM's reverse proxy at `https://raffles.xerramc.synology.me:5443`, forwarding to `localhost:5210`.

The log is append-only. The database refuses edits and deletions, and each entry is hashed together with the one before it, so changing any past entry breaks the chain and the Log tab says so.

## Deploying the server

Copy `server/` to `/volume1/docker/torn-raffles` on the NAS with a `wheels/` folder of Flask and gunicorn wheels (the War Codex folder has them), then:

```bash
sudo /usr/local/bin/docker compose up -d
```

`data/raffles.db` holds all the site's data and survives rebuilds.
