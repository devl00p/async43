class PywhoisError(Exception):
    pass

#backwards compatibility
class WhoisError(PywhoisError):
    pass

class WhoisNetworkError(WhoisError):
    pass


class WhoisInternalError(WhoisError):
    pass


class WhoisDomainNotFoundError(WhoisError):
    pass


class WhoisPolicyRestrictedError(WhoisError):
    """
    WHOIS access is intentionally restricted by the registry.
    The response is policy-based and does not reflect domain status.
    """
    pass


class FailedParsingWhoisOutputError(WhoisError):
    pass


class WhoisQuotaExceededError(WhoisError):
    pass


class WhoisUnknownDateFormatError(WhoisError):
    pass


class WhoisCommandFailedError(WhoisError):
    pass
