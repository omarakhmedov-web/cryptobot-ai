
MetridexBot upgrades (vFree2):
- Free = {"lifetime QuickScan": {"count": {"FREE_LIFETIME"}}} enforced via file storage.
- New commands: /upgrade, /limits, /report, /daypass.
- Slow lane for Free users: {"SLOW_LANE_MS_FREE"} ms.

ENV (add to .env or Render):
  FREE_LIFETIME=2
  PRO_MONTHLY=29
  TEAMS_MONTHLY=99
  DAY_PASS=9
  DEEP_REPORT=3
  PRO_OVERAGE_PER_100=5
  SLOW_LANE_MS_FREE=3000
  USAGE_PATH=/data/usage.json  # optional, else defaults to ./usage.json

Storage: JSON file at USAGE_PATH. For production, switch to Redis/DB by adapting _load_usage/_save_usage.
