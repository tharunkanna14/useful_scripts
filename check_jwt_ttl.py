import jwt
from datetime import datetime, timezone, timedelta

def get_jwt_ttl_info(jwt_string):
    """
    Decodes a JWT and returns information about its Time-To-Live (TTL).

    Args:
        jwt_string: The JWT string.

    Returns:
        A dictionary containing:
            - 'expiration_timestamp': The 'exp' claim value (Unix timestamp), or None if not found.
            - 'expiration_datetime_utc': The expiration datetime in UTC, or None if 'exp' is not found.
            - 'is_expired': True if the token is expired, False otherwise, or None if 'exp' is not found.
            - 'time_remaining': A timedelta object representing the time remaining until expiration,
                                or None if 'exp' is not found or already expired.
    """
    try:
        # You don't need to verify the signature to read the header and payload
        decoded_payload = jwt.decode(jwt_string, options={"verify_signature": False})
        expiration_timestamp = decoded_payload.get('exp')

        if expiration_timestamp is not None:
            expiration_datetime_utc = datetime.fromtimestamp(expiration_timestamp, tz=timezone.utc)
            now_utc = datetime.now(timezone.utc)
            is_expired = now_utc > expiration_datetime_utc

            if not is_expired:
                time_remaining = expiration_datetime_utc - now_utc
            else:
                time_remaining = timedelta(seconds=0)  # Already expired

            return {
                'expiration_timestamp': expiration_timestamp,
                'expiration_datetime_utc': expiration_datetime_utc,
                'is_expired': is_expired,
                'time_remaining': time_remaining if not is_expired else timedelta(seconds=0)
            }
        else:
            return {
                'expiration_timestamp': None,
                'expiration_datetime_utc': None,
                'is_expired': None,
                'time_remaining': None
            }

    except jwt.exceptions.DecodeError:
        return {
            'expiration_timestamp': None,
            'expiration_datetime_utc': None,
            'is_expired': None,
            'time_remaining': None,
            'error': 'Invalid JWT format'
        }
    except Exception as e:
        return {
            'expiration_timestamp': None,
            'expiration_datetime_utc': None,
            'is_expired': None,
            'time_remaining': None,
            'error': f'An unexpected error occurred: {e}'
        }

# Example usage:
if __name__ == "__main__":
    # Replace with a real JWT string for testing
    example_jwt = "xxx"

    ttl_info = get_jwt_ttl_info(example_jwt)

    if 'error' in ttl_info:
        print(f"Error: {ttl_info['error']}")
    else:
        print("JWT TTL Information:")
        if ttl_info['expiration_timestamp'] is not None:
            print(f"  Expiration Timestamp (Unix): {ttl_info['expiration_timestamp']}")
            print(f"  Expiration Datetime (UTC): {ttl_info['expiration_datetime_utc']}")
            print(f"  Is Expired: {ttl_info['is_expired']}")
            if not ttl_info['is_expired']:
                print(f"  Time Remaining: {ttl_info['time_remaining']}")
        else:
            print("  'exp' claim not found in the JWT.")