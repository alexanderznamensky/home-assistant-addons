# Changelog

## 0.4.4-garmin-di-config

- Added `scaleconnect_yaml` add-on option.
- `run.sh` now writes `/config/scaleconnect.yaml` from add-on options.
- Prevents restart loop with a clearer config error.

## 0.4.3-garmin-di

- Replaced old Garmin OAuth1 ticket authorization with Garmin DI OAuth2/Bearer token flow.
- Added DI token refresh.
- Added native Garmin mobile headers.
- Old Garmin tokens are no longer accepted.
