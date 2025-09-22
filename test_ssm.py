from aws_param_store import get_parameter
from botocore.exceptions import NoCredentialsError

# Mock fallback dictionary for local testing
mock_params = {
    "/n12008192/assessment2/COGNITO_CLIENT_ID": "test-client-id",
    "/n12008192/assessment2/COGNITO_CLIENT_SECRET": "test-client-secret"
}

def safe_get_parameter(name):
    """
    Try to get the parameter from AWS SSM.
    If credentials are not available, use the mock value.
    """
    try:
        value = get_parameter(name)
        if value is None:
            print(f"Parameter {name} not found in AWS, using mock value.")
            value = mock_params.get(name)
        return value
    except NoCredentialsError:
        print(f"No AWS credentials found, using mock value for {name}.")
        return mock_params.get(name)

if __name__ == "__main__":
    client_id = safe_get_parameter("/n12008192/assessment2/COGNITO_CLIENT_ID")
    client_secret = safe_get_parameter("/n12008192/assessment2/COGNITO_CLIENT_SECRET")

    print("COGNITO_CLIENT_ID:", client_id)
    print("COGNITO_CLIENT_SECRET:", client_secret)
