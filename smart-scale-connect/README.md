# Smart Scale Connect Garmin DI

Patched SmartScaleConnect add-on with updated Garmin authorization.

## Configuration

The application expects:

```text
/config/scaleconnect.yaml
```

Example:

```yaml
sync_picooc_to_garmin:
  from: picooc picooc@example.com picooc-password
  to: garmin garmin@example.com garmin-password
```

## Important

After switching from the official SmartScaleConnect build, delete old Garmin credentials from:

```text
/config/scaleconnect.json
```

or delete the whole file if you are ready to re-authorize all services.

The new token format is:

```text
di|client_id|access_token|refresh_token
```

The old token format:

```text
oauth_token:oauth_secret
```

is intentionally rejected.
