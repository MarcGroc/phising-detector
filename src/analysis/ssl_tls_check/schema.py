from pydantic import  BaseModel, PastDatetime, FutureDatetime



class SSLCHeckResult(BaseModel):
    is_valid: bool
    hostname_matches: bool
    valid_from: PastDatetime
    valid_to: FutureDatetime
    issued_by: str



