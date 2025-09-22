import os
import boto3
from botocore.exceptions import ClientError

region = "ap-southeast-2"
ssm = boto3.client("ssm", region_name=region)

def get_parameter(name, with_decryption=True, env_fallback=None):
    """
    Fetch a parameter from AWS SSM Parameter Store.
    Returns the value if found. If not found and env_fallback is provided, 
    returns the value from environment variables.
    """
    try:
        response = ssm.get_parameter(Name=name, WithDecryption=with_decryption)
        return response["Parameter"]["Value"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ParameterNotFound":
            print(f"Parameter {name} not found in SSM")
        else:
            print(f"Error retrieving {name}: {e}")
        
        if env_fallback:
            fallback_value = os.environ.get(env_fallback)
            if fallback_value:
                print(f"Using environment variable {env_fallback} as fallback")
                return fallback_value
        return None

if __name__ == "__main__":
    # Replace these with your actual parameter names
    client_id = get_parameter(
        "/n12008192/assessment2/COGNITO_CLIENT_ID", 
        env_fallback="COGNITO_CLIENT_ID"
    )
    client_secret = get_parameter(
        "/n12008192/assessment2/COGNITO_CLIENT_SECRET", 
        env_fallback="COGNITO_CLIENT_SECRET"
    )

    print("COGNITO_CLIENT_ID:", client_id)
    print("COGNITO_CLIENT_SECRET:", client_secret)
