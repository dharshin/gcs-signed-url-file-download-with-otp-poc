from datetime import timedelta
import json

from google import auth
from google.auth.transport import requests
from google.cloud.storage import Client

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

BUCKET='signedurl-poc-dds'

EXPIRE_AFTER_SECONDS=600

# Only for POC, this needs to come from a vault
KEY=b'\xf9[\x90\xb8\xb9@=\x1d\x82\xfe\xe8\xe9\x17\x8e\xd5{\xfa\xb2\x1d\x04\x16\xff;\x00!nqN`\xde-\x85'

CUSTOM_HOSTNAME=""

def generate_otp(file_name, user_id=''):
    '''
    Generates an OTP using the filename, user ID, content hash and a cryptographically secure random number.
    Just the random number should do it, but I'm being paranoid here. GCS API only validates the final value
    '''
    hmac = HMAC.new(KEY, digestmod=SHA256)
    
    hmac.update(
        bytes(file_name, "ASCII") +
        bytes(str(user_id), "ASCII") +
        get_random_bytes(32) # nonce
    )

    return hmac.hexdigest()


def download(request):
    """
    Returns a signed URL for file download and an OTP
    """

    file_name = ""
    request_json = request.get_json()
    if request_json and 'file-name' in request_json:
        file_name = request_json['file-name']

    else:
        # See if the filename is specified in the request
        return [500, '{"message": "Error! file-name not specified"}']


    uid = 0
    if request_json and 'user-id' in request_json:
        uid = int(request_json['user-id'])


    # Using the attached Service Account to authN 
    credentials, project_id = auth.default()
    if credentials.token is None:
        # Perform a refresh request to populate the access token of the
        # current credentials.
        credentials.refresh(requests.Request()) 

    # Mandatory request headers go here
    headers = {}

    # mandatory fields
    sign_request = {
        "version": "v4",
        "expiration": timedelta(seconds=EXPIRE_AFTER_SECONDS),
        "service_account_email": credentials.service_account_email,
        "access_token": credentials.token,
        "method": "GET"
    }


    if CUSTOM_HOSTNAME and len(CUSTOM_HOSTNAME) > 1:
        sign_request['bucket_bound_hostname']=CUSTOM_HOSTNAME
    else:
        sign_request['virtual_hosted_style']=True


    # Adding information in the request

    # Adding custom headers in the request
    if "headers" in request_json:
        try:
            for key, val in request_json['headers'].iteritems():
                headers[key] = str(val)
        except:
            #TODO: log what the issue is. but this is just for a PoC
            pass

    # adding the OTP header
    OTP = generate_otp(
        file_name, 
        user_id=uid,
    )

    headers['x-otp'] = OTP

    # Adding headers to the request

    sign_request['headers']=headers

    # Debugging
    # debug = sign_request.copy()
    # debug['access_token']='###' # should not output the token
    # debug['expiration']=str(EXP)


    # Connecting to the bucket and getting a handle to the file
    client = Client()
    bucket = client.get_bucket(BUCKET)
    
    object = bucket.blob(file_name)
    if object is None: # object does not exist
        return [404, '{"message": "Error! file-name not found"}']


    return json.dumps({
        'url': object.generate_signed_url(**sign_request),
        'otp': OTP,
        #'debug': debug,
        #'request': request.get_json()
    })
    