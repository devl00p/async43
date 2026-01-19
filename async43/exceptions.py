class PywhoisError(Exception):
    """
    Base exception for all errors raised by the pywhois/async43 package.

    This exception is not intended to be raised directly, but to serve as
    the root of the WHOIS-related exception hierarchy.
    """


# Backwards compatibility
class WhoisError(PywhoisError):
    """
    Base exception for WHOIS-related errors.

    This class exists primarily for backward compatibility and should be
    used as the common ancestor for all WHOIS exceptions.
    """


class WhoisNetworkError(WhoisError):
    """
    Raised when a network-level error occurs during a WHOIS operation.

    This includes DNS resolution failures, socket errors, and connection
    timeouts when contacting WHOIS servers.
    """


class WhoisInternalError(WhoisError):
    """
    Raised when an unexpected internal error occurs.

    This exception indicates a bug or an invalid internal state within
    the WHOIS client or parser.
    """


class WhoisNonRoutableIPError(WhoisError):
    """
    Raised when the input is a valid IP address but is not globally routable.

    This includes private, loopback, link-local, multicast, or reserved
    IP address ranges that cannot be queried via public WHOIS services.
    """


class WhoisDomainNotFoundError(WhoisError):
    """
    Raised when the requested domain does not exist or is not registered.

    This typically corresponds to a WHOIS response indicating that the
    domain name is available or unknown to the registry.
    """


class WhoisPolicyRestrictedError(WhoisError):
    """
    Raised when WHOIS access is restricted by registry policy.

    The returned WHOIS data is intentionally limited or obfuscated and
    does not reflect the actual domain registration status.
    """


class FailedParsingWhoisOutputError(WhoisError):
    """
    Raised when the WHOIS response cannot be parsed successfully.

    This indicates that the WHOIS output format is unsupported, malformed,
    or incompatible with the current parser implementation.
    """


class WhoisQuotaExceededError(WhoisError):
    """
    Raised when a WHOIS query quota or rate limit has been exceeded.

    This may be enforced by the registry or WHOIS server and usually
    requires waiting before retrying.
    """


class WhoisUnknownDateFormatError(WhoisError):
    """
    Raised when a date field in the WHOIS output cannot be parsed.

    This occurs when the date format is unknown or unsupported by the
    date parsing logic.
    """


class WhoisCommandFailedError(WhoisError):
    """
    Raised when execution of an external WHOIS command fails.

    This includes non-zero exit codes, missing executables, or invalid
    command-line options.
    """
