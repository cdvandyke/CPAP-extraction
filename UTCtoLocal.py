from datetime import datetime, timezone


def utc_to_local(utc_dt):
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)
########################################################################

dt = datetime.utcnow()
print(dt, ' UTC time')

dt = utc_to_local(dt)
print(dt, " Local Time")
print(dt.tzinfo)
